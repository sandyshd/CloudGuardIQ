"""Phase 4.0: onboarding session API tests."""

from __future__ import annotations

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
from cloudguardiq.tenants.onboarding_session_repository import (
    OnboardingSession,
    OnboardingSessionRepository,
)

pytestmark = pytest.mark.asyncio

HOME_TID = "11111111-1111-1111-1111-111111111111"
CUSTOMER_TID = "22222222-2222-2222-2222-222222222222"
SUB_GUID = "33333333-3333-3333-3333-333333333333"


def _wire(
    *,
    consent_repo: TenantConsentRepository | None = None,
    onboarding_repo: OnboardingSessionRepository | None = None,
) -> None:
    settings = Settings(azure_client_id="client-abc", auth_disabled=False)
    subs_repo = SubscriptionsRepository(settings, cosmos_db=None)
    billing_repo = BillingRepository(settings, cosmos_db=None)
    crepo = consent_repo or TenantConsentRepository(settings, cosmos_db=None)
    orepo = onboarding_repo or OnboardingSessionRepository(
        settings, cosmos_db=None,
    )
    subs_module.configure(
        repository=subs_repo,
        billing_repository=billing_repo,
        settings=settings,
        consent_repository=crepo,
        onboarding_session_repository=orepo,
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


async def test_create_session_starts_pending_consent_for_cross_tenant() -> None:
    _wire()
    client = _client()
    r = client.post(
        "/subscriptions/onboarding-sessions",
        json={"customer_tenant_id": CUSTOMER_TID},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["customer_tenant_id"] == CUSTOMER_TID
    assert body["status"] == "pending_consent"
    assert body["session_id"]
    assert f"state={body['session_id']}" in body["consent_url"]


async def test_create_session_same_tenant_skips_consent() -> None:
    _wire()
    client = _client()
    r = client.post(
        "/subscriptions/onboarding-sessions",
        json={"customer_tenant_id": HOME_TID},
    )
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "pending_reader"


async def test_get_session_auto_advances_when_consent_exists() -> None:
    consent_repo = TenantConsentRepository(Settings(), cosmos_db=None)
    onboarding_repo = OnboardingSessionRepository(Settings(), cosmos_db=None)
    _wire(consent_repo=consent_repo, onboarding_repo=onboarding_repo)

    session = OnboardingSession(
        session_id="sess-1",
        operator_tenant_id=HOME_TID,
        customer_tenant_id=CUSTOMER_TID,
        status="pending_consent",
    )
    await onboarding_repo.upsert(session)
    await consent_repo.upsert(TenantConsent(customer_tenant_id=CUSTOMER_TID))

    client = _client()
    r = client.get("/subscriptions/onboarding-sessions/sess-1")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "pending_reader"


async def test_consent_callback_advances_session_when_state_is_session_id() -> None:
    consent_repo = TenantConsentRepository(Settings(), cosmos_db=None)
    onboarding_repo = OnboardingSessionRepository(Settings(), cosmos_db=None)
    _wire(consent_repo=consent_repo, onboarding_repo=onboarding_repo)

    session = OnboardingSession(
        session_id="sess-2",
        operator_tenant_id=HOME_TID,
        customer_tenant_id=CUSTOMER_TID,
        status="pending_consent",
    )
    await onboarding_repo.upsert(session)

    client = _client()
    r = client.get(
        "/subscriptions/consent-callback",
        params={
            "tenant": CUSTOMER_TID,
            "admin_consent": "True",
            "state": "sess-2",
        },
    )
    assert r.status_code == 200, r.text
    saved = await onboarding_repo.get(HOME_TID, "sess-2")
    assert saved is not None
    assert saved.status == "pending_reader"


async def test_mark_reader_granted_transitions_session() -> None:
    onboarding_repo = OnboardingSessionRepository(Settings(), cosmos_db=None)
    _wire(onboarding_repo=onboarding_repo)
    await onboarding_repo.upsert(OnboardingSession(
        session_id="sess-3",
        operator_tenant_id=HOME_TID,
        customer_tenant_id=CUSTOMER_TID,
        status="pending_reader",
    ))

    client = _client()
    r = client.post("/subscriptions/onboarding-sessions/sess-3/reader-granted")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "pending_discovery"


async def test_connect_uses_discovered_ids_and_marks_completed(monkeypatch) -> None:
    onboarding_repo = OnboardingSessionRepository(Settings(), cosmos_db=None)
    _wire(onboarding_repo=onboarding_repo)
    await onboarding_repo.upsert(OnboardingSession(
        session_id="sess-4",
        operator_tenant_id=HOME_TID,
        customer_tenant_id=CUSTOMER_TID,
        status="subscriptions_discovered",
        discovered_subscription_ids=[SUB_GUID],
    ))

    async def _fake_add(body, user):  # noqa: ANN001
        return subs_module.SubscriptionResponse(
            subscription_id=body.subscription_id,
            display_name=body.subscription_id,
            state="Enabled",
        )

    monkeypatch.setattr(subs_module, "add_subscription", _fake_add)
    client = _client()
    r = client.post("/subscriptions/onboarding-sessions/sess-4/connect", json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "completed"
    assert body["connected_subscription_ids"] == [SUB_GUID]
