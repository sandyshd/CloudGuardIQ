"""AWS onboarding via POST /subscriptions."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from cloudguardiq.api import subscriptions as subs_module
from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.api.main import app
from cloudguardiq.billing.repository import BillingCustomer, BillingRepository
from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import CloudProvider, SubscriptionTier
from cloudguardiq.subscriptions.repository import SubscriptionsRepository


def _wire(tier: SubscriptionTier | None = None) -> SubscriptionsRepository:
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
    return subs_repo


@pytest.fixture(autouse=True)
def _override_auth() -> None:
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid="tenant-A"
    )
    yield
    app.dependency_overrides.clear()


def test_add_aws_subscription_with_valid_account_id() -> None:
    subs_repo = _wire()
    client = TestClient(app)
    r = client.post(
        "/subscriptions",
        json={
            "provider": "aws",
            "aws_account_id": "111122223333",
            "aws_region": "us-west-2",
            "display_name": "Prod AWS",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["provider"] == "aws"
    assert body["aws_account_id"] == "111122223333"
    assert body["aws_region"] == "us-west-2"
    assert body["subscription_id"] == "111122223333"
    assert body["display_name"] == "Prod AWS"

    # Record is persisted with CloudProvider.AWS
    stored = asyncio.run(subs_repo.get("tenant-A", "111122223333"))
    assert stored is not None
    assert stored.provider is CloudProvider.AWS
    assert stored.aws_account_id == "111122223333"
    assert stored.aws_region == "us-west-2"


def test_add_aws_defaults_region_when_omitted() -> None:
    _wire()
    client = TestClient(app)
    r = client.post(
        "/subscriptions",
        json={"provider": "aws", "aws_account_id": "444455556666"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["aws_region"] == "us-east-1"


def test_add_aws_rejects_non_numeric_account_id() -> None:
    _wire()
    client = TestClient(app)
    r = client.post(
        "/subscriptions",
        json={"provider": "aws", "aws_account_id": "not-a-number"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_aws_account_id"


def test_add_aws_rejects_short_account_id() -> None:
    _wire()
    client = TestClient(app)
    r = client.post(
        "/subscriptions",
        json={"provider": "aws", "aws_account_id": "123"},
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_aws_account_id"


def test_add_aws_rejects_malformed_region() -> None:
    _wire()
    client = TestClient(app)
    r = client.post(
        "/subscriptions",
        json={
            "provider": "aws",
            "aws_account_id": "111122223333",
            "aws_region": "USEAST1",
        },
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "invalid_aws_region"


def test_aws_onboarding_enforces_tier_cap() -> None:
    """FREE tier cap (default 1) blocks the second AWS account."""
    _wire(tier=SubscriptionTier.FREE)
    client = TestClient(app)
    r1 = client.post(
        "/subscriptions",
        json={"provider": "aws", "aws_account_id": "111122223333"},
    )
    assert r1.status_code == 201, r1.text
    r2 = client.post(
        "/subscriptions",
        json={"provider": "aws", "aws_account_id": "444455556666"},
    )
    assert r2.status_code == 402
    assert r2.json()["detail"]["error"] == "upgrade_required"


def test_aws_listing_surfaces_provider_in_response() -> None:
    _wire()
    client = TestClient(app)
    client.post(
        "/subscriptions",
        json={"provider": "aws", "aws_account_id": "111122223333"},
    )
    listed = client.get("/subscriptions").json()
    assert any(
        item["provider"] == "aws" and item["aws_account_id"] == "111122223333"
        for item in listed
    )


def test_azure_default_path_still_returns_provider_azure() -> None:
    """Backward compat: existing Azure POSTs surface provider=azure."""
    _wire()
    client = TestClient(app)
    r = client.post(
        "/subscriptions",
        json={"subscription_id": "11111111-1111-1111-1111-111111111111"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["provider"] == "azure"
    assert body["aws_account_id"] == ""
