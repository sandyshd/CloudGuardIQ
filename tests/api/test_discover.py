"""Tests for the simpler one-click onboarding flow.

Covers GET /subscriptions/discover and GET /subscriptions/onboarding-template
added in Phase 3.9.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from urllib.parse import unquote

import pytest
from fastapi.testclient import TestClient

from cloudguardiq.api import subscriptions as subs_module
from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.api.main import app
from cloudguardiq.billing.repository import BillingRepository
from cloudguardiq.core.config import Settings
from cloudguardiq.subscriptions.repository import (
    SubscriptionRecord,
    SubscriptionsRepository,
)
from cloudguardiq.tenants.consent_repository import (
    TenantConsent,
    TenantConsentRepository,
)

HOME_TID = "11111111-1111-1111-1111-111111111111"
CUSTOMER_TID = "22222222-2222-2222-2222-222222222222"
SUB1 = "33333333-3333-3333-3333-333333333333"
SUB2 = "44444444-4444-4444-4444-444444444444"
TEMPLATE_URI = "https://raw.example.com/cloudguardiq-reader.json"


class _StubSub:
    def __init__(self, sub_id: str, name: str, state: str = "Enabled") -> None:
        self.subscription_id = sub_id
        self.display_name = name
        self.state = state


class _StubFactory:
    """Stub credential factory; records the tenant it was called for."""

    def __init__(self) -> None:
        self.last_tenant: str | None = None

    def for_tenant(self, tenant_id: str) -> object:
        self.last_tenant = tenant_id
        return object()


def _wire(
    *,
    consent_repo: TenantConsentRepository | None = None,
    factory: _StubFactory | None = None,
    template_uri: str = TEMPLATE_URI,
    seeded: list[SubscriptionRecord] | None = None,
) -> tuple[SubscriptionsRepository, _StubFactory]:
    settings = Settings(
        azure_client_id="client-abc",
        onboarding_template_uri=template_uri,
        azure_principal_id="00000000-0000-0000-0000-0000000000aa",
    )
        # Conftest sets CLOUDGUARDIQ_AUTH_DISABLED=true; override so the
    # consent + cross-tenant guards behave like production.
    settings.auth_disabled = False
    subs_repo = SubscriptionsRepository(settings, cosmos_db=None)
    if seeded:
        import asyncio
        for rec in seeded:
            asyncio.run(subs_repo.upsert(rec))
    billing_repo = BillingRepository(settings, cosmos_db=None)
    repo = consent_repo or TenantConsentRepository(settings, cosmos_db=None)
    fac = factory or _StubFactory()
    subs_module.configure(
        repository=subs_repo,
        billing_repository=billing_repo,
        settings=settings,
        consent_repository=repo,
        credential_factory=fac,
    )
    return subs_repo, fac


@pytest.fixture(autouse=True)
def _override_auth() -> Iterator[None]:
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def _client() -> TestClient:
    return TestClient(app)


def _seed_consent(tid: str = CUSTOMER_TID) -> TenantConsentRepository:
    repo = TenantConsentRepository(Settings(), cosmos_db=None)
    import asyncio
    asyncio.run(
        repo.upsert(TenantConsent(customer_tenant_id=tid, consented_by="oid-x")),
    )
    return repo


# ---------------------------------------------------------------------------
# /subscriptions/discover
# ---------------------------------------------------------------------------


def test_discover_requires_consent_for_foreign_tenant(_client: TestClient) -> None:
    _wire()  # no consent recorded
    r = _client.get(f"/subscriptions/discover?tenant_id={CUSTOMER_TID}")
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["error"] == "consent_required"


def test_discover_returns_subscriptions(
    _client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _seed_consent()
    _wire(consent_repo=repo)

    async def _fake_list(_credential: Any) -> list[Any]:
        from cloudguardiq.api.subscriptions import DiscoveredSubscription
        return [
            DiscoveredSubscription(subscription_id=SUB1, display_name="Prod"),
            DiscoveredSubscription(subscription_id=SUB2, display_name="Dev"),
        ]

    monkeypatch.setattr(
        subs_module, "_list_customer_subscriptions", _fake_list,
    )
    r = _client.get(f"/subscriptions/discover?tenant_id={CUSTOMER_TID}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["customer_tenant_id"] == CUSTOMER_TID
    assert {s["subscription_id"] for s in body["subscriptions"]} == {SUB1, SUB2}
    assert all(s["already_linked"] is False for s in body["subscriptions"])


def test_discover_marks_already_linked(
    _client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _seed_consent()
    seeded = [SubscriptionRecord(
        tenant_id=HOME_TID, subscription_id=SUB1, display_name="Prod",
        customer_tenant_id=CUSTOMER_TID,
    )]
    _wire(consent_repo=repo, seeded=seeded)

    async def _fake_list(_credential: Any) -> list[Any]:
        from cloudguardiq.api.subscriptions import DiscoveredSubscription
        return [
            DiscoveredSubscription(subscription_id=SUB1, display_name="Prod"),
            DiscoveredSubscription(subscription_id=SUB2, display_name="Dev"),
        ]

    monkeypatch.setattr(
        subs_module, "_list_customer_subscriptions", _fake_list,
    )
    r = _client.get(f"/subscriptions/discover?tenant_id={CUSTOMER_TID}")
    assert r.status_code == 200, r.text
    by_id = {s["subscription_id"]: s for s in r.json()["subscriptions"]}
    assert by_id[SUB1]["already_linked"] is True
    assert by_id[SUB2]["already_linked"] is False


def test_discover_403_returns_reader_role_required(
    _client: TestClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _seed_consent()
    _wire(consent_repo=repo)

    async def _boom(_credential: Any) -> list[Any]:
        raise RuntimeError("AuthorizationFailed: SP has no role at scope ...")

    monkeypatch.setattr(subs_module, "_list_customer_subscriptions", _boom)
    r = _client.get(f"/subscriptions/discover?tenant_id={CUSTOMER_TID}")
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert detail["error"] == "reader_role_required"
    assert detail["template_uri"] == TEMPLATE_URI
    assert "portal.azure.com" in detail["deploy_url"]
    assert TEMPLATE_URI in unquote(detail["deploy_url"])


def test_discover_factory_not_configured(_client: TestClient) -> None:
    repo = _seed_consent()
    settings = Settings(azure_client_id="client-abc")
    subs_repo = SubscriptionsRepository(settings, cosmos_db=None)
    billing_repo = BillingRepository(settings, cosmos_db=None)
    subs_module.configure(
        repository=subs_repo,
        billing_repository=billing_repo,
        settings=settings,
        consent_repository=repo,
        credential_factory=None,
    )
    r = _client.get(f"/subscriptions/discover?tenant_id={CUSTOMER_TID}")
    assert r.status_code == 503, r.text


# ---------------------------------------------------------------------------
# /subscriptions/onboarding-template
# ---------------------------------------------------------------------------


def test_onboarding_template_returns_deploy_url(_client: TestClient) -> None:
    _wire()
    r = _client.get("/subscriptions/onboarding-template")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["template_uri"] == TEMPLATE_URI
    assert body["scope"] == "managementGroup"
    assert "DeployToAzureMgBlade" in body["deploy_url"]
    assert TEMPLATE_URI in unquote(body["deploy_url"])
    assert body["azure_principal_id"]


def test_onboarding_template_subscription_scope(_client: TestClient) -> None:
    _wire()
    r = _client.get("/subscriptions/onboarding-template?scope=subscription")
    assert r.status_code == 200, r.text
    assert "Microsoft.Template/uri" in r.json()["deploy_url"]


def test_onboarding_template_invalid_scope(_client: TestClient) -> None:
    _wire()
    r = _client.get("/subscriptions/onboarding-template?scope=resource")
    assert r.status_code == 400


def test_onboarding_template_unconfigured(_client: TestClient) -> None:
    _wire(template_uri="")
    r = _client.get("/subscriptions/onboarding-template")
    assert r.status_code == 503
