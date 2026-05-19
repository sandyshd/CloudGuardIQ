"""Phase 3.3 / 3.4: cross-tenant consent and onboarding tests."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from cloudguardiq.api import subscriptions as subs_module
from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.api.main import app
from cloudguardiq.billing.repository import BillingRepository
from cloudguardiq.core.config import Settings
from cloudguardiq.subscriptions.repository import SubscriptionsRepository
from cloudguardiq.tenants.consent_repository import (
    TenantConsent,
    TenantConsentRepository,
)

HOME_TID = "11111111-1111-1111-1111-111111111111"
CUSTOMER_TID = "22222222-2222-2222-2222-222222222222"
SUB_GUID = "33333333-3333-3333-3333-333333333333"


def _wire(consent_repo: TenantConsentRepository | None = None) -> None:
    settings = Settings(azure_client_id="client-abc")
    subs_repo = SubscriptionsRepository(settings, cosmos_db=None)
    billing_repo = BillingRepository(settings, cosmos_db=None)
    repo = consent_repo or TenantConsentRepository(settings, cosmos_db=None)
    subs_module.configure(
        repository=subs_repo,
        billing_repository=billing_repo,
        settings=settings,
        consent_repository=repo,
    )


@pytest.fixture(autouse=True)
def _override_auth() -> None:
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    yield
    app.dependency_overrides.clear()


def _client() -> TestClient:
    return TestClient(app)


def test_consent_url_returns_admin_consent_link() -> None:
    _wire()
    client = _client()
    r = client.get(f"/subscriptions/consent-url?tenant_id={CUSTOMER_TID}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["customer_tenant_id"] == CUSTOMER_TID
    assert "login.microsoftonline.com" in body["consent_url"]
    assert CUSTOMER_TID in body["consent_url"]
    assert "client_id=client-abc" in body["consent_url"]
    assert "adminconsent" in body["consent_url"]


def test_consent_url_rejects_invalid_tenant() -> None:
    _wire()
    client = _client()
    r = client.get("/subscriptions/consent-url?tenant_id=not-a-guid")
    assert r.status_code == 400


def test_consent_callback_records_tenant() -> None:
    consent_repo = TenantConsentRepository(Settings(), cosmos_db=None)
    _wire(consent_repo=consent_repo)
    client = _client()
    r = client.get(
        "/subscriptions/consent-callback",
        params={"tenant": CUSTOMER_TID, "admin_consent": "True"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["customer_tenant_id"] == CUSTOMER_TID
    assert body["status"] == "recorded"
    # Verify the record landed in the repo
    saved = asyncio.run(consent_repo.get(CUSTOMER_TID))
    assert saved is not None
    assert saved.is_active
    assert saved.consented_by == "oid-1"


def test_consent_callback_rejects_when_not_granted() -> None:
    _wire()
    client = _client()
    r = client.get(
        "/subscriptions/consent-callback",
        params={"tenant": CUSTOMER_TID, "admin_consent": "False"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "consent_not_granted"


def test_consent_callback_surfaces_aad_error() -> None:
    _wire()
    client = _client()
    r = client.get(
        "/subscriptions/consent-callback",
        params={
            "tenant": CUSTOMER_TID,
            "error": "access_denied",
            "error_description": "user declined",
        },
    )
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert detail["error"] == "consent_failed"
    assert detail["azure_error"] == "access_denied"


def test_add_subscription_blocked_without_consent_for_other_tenant(
    monkeypatch,
) -> None:
    """Cross-tenant POST without consent recorded must return 400."""
    _wire()
    monkeypatch.setattr(
        "cloudguardiq.api.subscriptions._get_settings",
        lambda: type("S", (), {"auth_disabled": False, "azure_client_id": "x"})(),
    )
    client = _client()
    r = client.post(
        "/subscriptions",
        json={
            "subscription_id": SUB_GUID,
            "customer_tenant_id": CUSTOMER_TID,
        },
    )
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["error"] == "consent_required"


def test_add_subscription_succeeds_for_other_tenant_with_consent(
    monkeypatch,
) -> None:
    """After consent, cross-tenant add stores under customer ownership."""
    consent_repo = TenantConsentRepository(Settings(), cosmos_db=None)
    asyncio.run(consent_repo.upsert(
        TenantConsent(customer_tenant_id=CUSTOMER_TID),
    ))
    _wire(consent_repo=consent_repo)

    monkeypatch.setattr(
        "cloudguardiq.api.subscriptions._get_settings",
        lambda: type("S", (), {"auth_disabled": True, "azure_client_id": "x"})(),
    )
    client = _client()
    r = client.post(
        "/subscriptions",
        json={
            "subscription_id": SUB_GUID,
            "customer_tenant_id": CUSTOMER_TID,
            "display_name": "customer-prod",
        },
    )
    assert r.status_code == 201, r.text
    # Verify record is owned by customer tenant
    repo = subs_module._repository  # noqa: SLF001
    rec = asyncio.run(repo.get(CUSTOMER_TID, SUB_GUID))
    assert rec is not None
    assert rec.customer_tenant_id == CUSTOMER_TID


def test_add_subscription_same_tenant_skips_consent_check(monkeypatch) -> None:
    """When customer_tenant_id matches caller's tid, consent is not required."""
    _wire()
    monkeypatch.setattr(
        "cloudguardiq.api.subscriptions._get_settings",
        lambda: type("S", (), {"auth_disabled": True, "azure_client_id": "x"})(),
    )
    client = _client()
    r = client.post(
        "/subscriptions",
        json={
            "subscription_id": SUB_GUID,
            "customer_tenant_id": HOME_TID,  # same as caller
        },
    )
    assert r.status_code == 201, r.text
