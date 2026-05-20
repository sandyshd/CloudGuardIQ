"""GCP-focused tests for v1 onboarding session endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cloudguardiq.api import subscriptions as subs_module
from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.api.main import app
from cloudguardiq.billing.repository import BillingRepository
from cloudguardiq.core.config import Settings
from cloudguardiq.subscriptions.repository import SubscriptionsRepository
from cloudguardiq.tenants.consent_repository import TenantConsentRepository
from cloudguardiq.tenants.onboarding_session_repository import (
    OnboardingSessionRepository,
)

HOME_TID = "11111111-1111-1111-1111-111111111111"
GCP_PROJECT_ID = "proj-main-01"


def _wire(*, onboarding_template_uri: str = "https://raw.example.com/reader.json") -> None:
    settings = Settings(
        azure_tenant_id=HOME_TID,
        azure_client_id="client-abc",
        onboarding_template_uri=onboarding_template_uri,
        auth_disabled=False,
    )
    subs_repo = SubscriptionsRepository(settings, cosmos_db=None)
    billing_repo = BillingRepository(settings, cosmos_db=None)
    consent_repo = TenantConsentRepository(settings, cosmos_db=None)
    onboarding_repo = OnboardingSessionRepository(settings, cosmos_db=None)
    subs_module.configure(
        repository=subs_repo,
        billing_repository=billing_repo,
        settings=settings,
        consent_repository=consent_repo,
        onboarding_session_repository=onboarding_repo,
    )


def _client() -> TestClient:
    return TestClient(app)


def _create_gcp_session(client: TestClient) -> str:
    res = client.post(
        "/v1/onboarding/sessions",
        json={
            "provider": "GCP",
            "display_name": "Acme GCP",
            "target_scope": {"project_id": GCP_PROJECT_ID},
        },
    )
    assert res.status_code == 201, res.text
    return res.json()["session_id"]


def test_v1_create_session_accepts_gcp_project() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()

    res = client.post(
        "/v1/onboarding/sessions",
        json={
            "provider": "GCP",
            "display_name": "Acme GCP",
            "target_scope": {"project_id": GCP_PROJECT_ID},
        },
    )

    assert res.status_code == 201, res.text
    body = res.json()
    assert body["provider"] == "GCP"
    assert body["status"] == "initiated"
    assert "generate_artifacts" in body["next_actions"]
    app.dependency_overrides.clear()


def test_v1_create_gcp_rejects_invalid_project_id() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()

    res = client.post(
        "/v1/onboarding/sessions",
        json={
            "provider": "GCP",
            "display_name": "Acme GCP",
            "target_scope": {"project_id": "BAD"},
        },
    )

    assert res.status_code == 400, res.text
    assert res.json()["detail"]["error_code"] == "invalid_target_scope"
    app.dependency_overrides.clear()


def test_v1_generate_artifacts_for_gcp_returns_wif_details() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()
    session_id = _create_gcp_session(client)

    res = client.post(f"/v1/onboarding/sessions/{session_id}/generate-artifacts")

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["provider"] == "GCP"
    assert body["status"] == "trust_pending"
    assert body["artifacts"]["workload_identity_pool"]
    assert body["artifacts"]["provider_resource_name"]
    assert body["artifacts"]["gcloud_bind_command"]
    app.dependency_overrides.clear()


def test_v1_verify_for_gcp_returns_project_scope() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()
    session_id = _create_gcp_session(client)

    res = client.post(f"/v1/onboarding/sessions/{session_id}/verify")

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["provider"] == "GCP"
    assert body["status"] == "verified"
    assert body["discovered_scopes"][0]["id"] == GCP_PROJECT_ID
    app.dependency_overrides.clear()


def test_v1_connect_for_gcp_marks_connected() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()
    session_id = _create_gcp_session(client)
    client.post(f"/v1/onboarding/sessions/{session_id}/verify")

    res = client.post(
        f"/v1/onboarding/sessions/{session_id}/connect",
        json={"scope_ids": [GCP_PROJECT_ID]},
    )

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["provider"] == "GCP"
    assert body["status"] == "connected"
    assert body["linked_scope_ids"] == [GCP_PROJECT_ID]
    app.dependency_overrides.clear()
