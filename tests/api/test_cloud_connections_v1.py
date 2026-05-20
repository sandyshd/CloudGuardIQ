"""Tests for v1 cloud connection lifecycle endpoints."""

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
AWS_ACCOUNT_ID = "123456789012"


def _wire() -> None:
    settings = Settings(
        azure_tenant_id=HOME_TID,
        azure_client_id="client-abc",
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


def _connect_aws(client: TestClient) -> str:
    created = client.post(
        "/v1/onboarding/sessions",
        json={
            "provider": "AWS",
            "display_name": "Acme",
            "target_scope": {"account_id": AWS_ACCOUNT_ID},
        },
    )
    assert created.status_code == 201, created.text
    session_id = created.json()["session_id"]

    verified = client.post(f"/v1/onboarding/sessions/{session_id}/verify")
    assert verified.status_code == 200, verified.text

    connected = client.post(
        f"/v1/onboarding/sessions/{session_id}/connect",
        json={"scope_ids": [AWS_ACCOUNT_ID]},
    )
    assert connected.status_code == 200, connected.text
    connection_id = connected.json().get("connection_id", "")
    assert connection_id
    return connection_id


def test_cloud_connections_list_get_refresh_disconnect() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1",
        tid=HOME_TID,
        oid="oid-1",
    )
    client = _client()

    connection_id = _connect_aws(client)

    listed = client.get("/v1/cloud-connections")
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert any(r["connection_id"] == connection_id for r in rows)

    got = client.get(f"/v1/cloud-connections/{connection_id}")
    assert got.status_code == 200, got.text
    one = got.json()
    assert one["provider"] == "AWS"
    assert one["status"] == "active"

    refreshed = client.post(f"/v1/cloud-connections/{connection_id}/refresh")
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["status"] == "active"

    disconnected = client.delete(f"/v1/cloud-connections/{connection_id}")
    assert disconnected.status_code == 204, disconnected.text

    after = client.get(f"/v1/cloud-connections/{connection_id}")
    assert after.status_code == 200, after.text
    assert after.json()["status"] == "disconnected"

    app.dependency_overrides.clear()
