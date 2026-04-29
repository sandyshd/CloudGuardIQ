"""Phase 2: subscription routes tests."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from cloudguardiq.api import subscriptions as subs_module
from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.api.main import app
from cloudguardiq.billing.repository import BillingCustomer, BillingRepository
from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import SubscriptionTier
from cloudguardiq.subscriptions.repository import SubscriptionsRepository


def _wire(tier: SubscriptionTier | None = None) -> None:
    """Wire the subscriptions module with in-memory repos.

    Called *after* the TestClient is constructed because TestClient's
    lifespan hook re-configures the module with the real Cosmos bootstrap
    repos and would otherwise clobber the in-memory wiring.
    """
    settings = Settings()
    subs_repo = SubscriptionsRepository(settings, cosmos_db=None)
    billing_repo = BillingRepository(settings, cosmos_db=None)
    if tier is not None:
        asyncio.run(billing_repo.upsert(BillingCustomer(
            tenant_id="tenant-A", tier=tier,
        )))
    subs_module.configure(
        repository=subs_repo,
        billing_repository=billing_repo,
        settings=settings,
    )


@pytest.fixture(autouse=True)
def _override_auth() -> None:
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid="tenant-A"
    )
    yield
    app.dependency_overrides.clear()


def _client() -> TestClient:
    """Build a TestClient that does NOT execute the app lifespan."""
    # Use raise_server_exceptions=True (default) but skip lifespan by not
    # using the context-manager form.
    return TestClient(app)


def test_list_empty() -> None:
    _wire()
    client = _client()
    r = client.get("/subscriptions")
    assert r.status_code == 200
    assert r.json() == []


def test_add_subscription() -> None:
    _wire()
    client = _client()
    r = client.post(
        "/subscriptions",
        json={
            "subscription_id": "11111111-1111-1111-1111-111111111111",
            "display_name": "Prod",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["subscription_id"] == "11111111-1111-1111-1111-111111111111"
    assert body["display_name"] == "Prod"
    assert body["state"] == "Enabled"


def test_add_rejects_invalid_guid() -> None:
    _wire()
    client = _client()
    r = client.post(
        "/subscriptions",
        json={"subscription_id": "not-a-guid", "display_name": "x"},
    )
    assert r.status_code in (400, 422)


def test_add_enforces_free_cap_of_1() -> None:
    _wire()
    client = _client()
    r1 = client.post(
        "/subscriptions",
        json={"subscription_id": "11111111-1111-1111-1111-111111111111"},
    )
    assert r1.status_code == 201
    r2 = client.post(
        "/subscriptions",
        json={"subscription_id": "22222222-2222-2222-2222-222222222222"},
    )
    assert r2.status_code == 402
    assert r2.json()["detail"]["error"] == "upgrade_required"


def test_pro_cap_is_10() -> None:
    _wire(tier=SubscriptionTier.PRO)
    client = _client()
    for i in range(10):
        sid = f"{i:08d}-1111-1111-1111-111111111111"
        r = client.post("/subscriptions", json={"subscription_id": sid})
        assert r.status_code == 201, f"add #{i} failed: {r.text}"
    r = client.post(
        "/subscriptions",
        json={"subscription_id": "99999999-9999-9999-9999-999999999999"},
    )
    assert r.status_code == 402


def test_delete_subscription() -> None:
    _wire()
    client = _client()
    sid = "11111111-1111-1111-1111-111111111111"
    client.post("/subscriptions", json={"subscription_id": sid})
    r = client.delete(f"/subscriptions/{sid}")
    assert r.status_code == 204
    assert client.get("/subscriptions").json() == []


def test_patch_state_disabled() -> None:
    _wire()
    client = _client()
    sid = "11111111-1111-1111-1111-111111111111"
    client.post("/subscriptions", json={"subscription_id": sid})
    r = client.patch(f"/subscriptions/{sid}", json={"state": "Disabled"})
    assert r.status_code == 200
    assert r.json()["state"] == "Disabled"


def test_tenant_isolation_other_tenant_cannot_delete() -> None:
    _wire()
    client = _client()
    sid = "11111111-1111-1111-1111-111111111111"
    client.post("/subscriptions", json={"subscription_id": sid})
    # Switch caller to different tenant
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-2", tid="tenant-B"
    )
    r = client.delete(f"/subscriptions/{sid}")
    assert r.status_code == 404  # not found in tenant-B
