"""Tests for v1 unified onboarding session endpoints."""

from __future__ import annotations

from typing import Any

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
CUSTOMER_TID = "22222222-2222-2222-2222-222222222222"
SUB_GUID = "33333333-3333-3333-3333-333333333333"
AWS_ACCOUNT_ID = "123456789012"


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


def _create_azure_session(client: TestClient) -> str:
    res = client.post(
        "/v1/onboarding/sessions",
        json={
            "provider": "AZURE",
            "display_name": "Contoso",
            "target_scope": {"tenant_id": CUSTOMER_TID},
        },
    )
    assert res.status_code == 201, res.text
    return res.json()["session_id"]


def _create_aws_session(client: TestClient) -> str:
    res = client.post(
        "/v1/onboarding/sessions",
        json={
            "provider": "AWS",
            "display_name": "Acme",
            "target_scope": {"account_id": AWS_ACCOUNT_ID},
        },
    )
    assert res.status_code == 201, res.text
    return res.json()["session_id"]


def test_v1_create_session_returns_envelope() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()

    res = client.post(
        "/v1/onboarding/sessions",
        json={
            "provider": "AZURE",
            "display_name": "Contoso",
            "target_scope": {"tenant_id": CUSTOMER_TID},
        },
    )

    assert res.status_code == 201, res.text
    body = res.json()
    assert body["provider"] == "AZURE"
    assert body["status"] == "consent_pending"
    assert body["session_id"]
    assert "generate_artifacts" in body["next_actions"]
    app.dependency_overrides.clear()


def test_v1_create_session_accepts_aws_account() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()

    res = client.post(
        "/v1/onboarding/sessions",
        json={
            "provider": "AWS",
            "display_name": "Acme",
            "target_scope": {"account_id": AWS_ACCOUNT_ID},
        },
    )

    assert res.status_code == 201, res.text
    body = res.json()
    assert body["provider"] == "AWS"
    assert body["status"] == "initiated"
    assert "generate_artifacts" in body["next_actions"]
    app.dependency_overrides.clear()


def test_v1_create_aws_rejects_invalid_account_id() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()

    res = client.post(
        "/v1/onboarding/sessions",
        json={
            "provider": "AWS",
            "display_name": "Acme",
            "target_scope": {"account_id": "abc"},
        },
    )

    assert res.status_code == 400, res.text
    detail = res.json()["detail"]
    assert detail["error_code"] == "invalid_target_scope"
    app.dependency_overrides.clear()


def test_v1_create_rejects_unknown_provider_value() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()

    res = client.post(
        "/v1/onboarding/sessions",
        json={
            "provider": "TERRAFORM",
            "display_name": "Acme",
            "target_scope": {"project_id": "my-proj-01"},
        },
    )

    assert res.status_code == 422, res.text
    app.dependency_overrides.clear()


def test_v1_generate_artifacts_returns_consent_and_deploy_info(
    monkeypatch: Any,
) -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()
    session_id = _create_azure_session(client)

    async def _fake_template(*_: Any, **__: Any) -> Any:
        return subs_module.OnboardingTemplateResponse(
            customer_tenant_id=CUSTOMER_TID,
            azure_principal_id="aaaa",
            template_uri="https://raw.example.com/template.json",
            deploy_url="https://portal.azure.com/#create/Microsoft.Template/uri/xxx",
            scope="managementGroup",
        )

    monkeypatch.setattr(subs_module, "get_onboarding_template", _fake_template)

    res = client.post(f"/v1/onboarding/sessions/{session_id}/generate-artifacts")

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["artifacts"]["consent_url"].startswith("https://login.microsoftonline.com")
    assert body["artifacts"]["deploy_url"].startswith("https://portal.azure.com")
    app.dependency_overrides.clear()


def test_v1_generate_artifacts_for_aws_returns_trust_template() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()
    session_id = _create_aws_session(client)

    res = client.post(f"/v1/onboarding/sessions/{session_id}/generate-artifacts")

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["provider"] == "AWS"
    assert body["status"] == "trust_pending"
    assert body["artifacts"]["trust_policy_json"]
    assert body["artifacts"]["aws_external_id"]
    app.dependency_overrides.clear()


def test_v1_verify_discovers_and_marks_verified(monkeypatch: Any) -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()
    session_id = _create_azure_session(client)

    async def _fake_discover(*_: Any, **__: Any) -> Any:
        return subs_module.OnboardingSessionResponse(
            session_id=session_id,
            customer_tenant_id=CUSTOMER_TID,
            status="subscriptions_discovered",
            consent_url="https://example.com/consent",
            discovered_subscription_ids=[SUB_GUID],
            connected_subscription_ids=[],
        )

    monkeypatch.setattr(
        subs_module,
        "discover_onboarding_session_subscriptions",
        _fake_discover,
    )

    res = client.post(f"/v1/onboarding/sessions/{session_id}/verify")

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "verified"
    assert body["discovered_scopes"][0]["id"] == SUB_GUID
    app.dependency_overrides.clear()


def test_v1_verify_for_aws_returns_account_scope() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()
    session_id = _create_aws_session(client)

    res = client.post(f"/v1/onboarding/sessions/{session_id}/verify")

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["provider"] == "AWS"
    assert body["status"] == "verified"
    assert body["discovered_scopes"][0]["id"] == AWS_ACCOUNT_ID
    app.dependency_overrides.clear()


def test_v1_connect_links_and_marks_connected(monkeypatch: Any) -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()
    session_id = _create_azure_session(client)

    async def _fake_connect(session_id: str, body: Any, user: Any) -> Any:  # noqa: ANN001
        return subs_module.OnboardingSessionResponse(
            session_id=session_id,
            customer_tenant_id=CUSTOMER_TID,
            status="completed",
            consent_url="https://example.com/consent",
            discovered_subscription_ids=[SUB_GUID],
            connected_subscription_ids=body.subscription_ids,
        )

    monkeypatch.setattr(
        subs_module,
        "connect_onboarding_session_subscriptions",
        _fake_connect,
    )

    res = client.post(
        f"/v1/onboarding/sessions/{session_id}/connect",
        json={"scope_ids": [SUB_GUID]},
    )

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "connected"
    assert body["linked_scope_ids"] == [SUB_GUID]
    app.dependency_overrides.clear()


def test_v1_connect_for_aws_marks_connected() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()
    session_id = _create_aws_session(client)
    client.post(f"/v1/onboarding/sessions/{session_id}/verify")

    res = client.post(
        f"/v1/onboarding/sessions/{session_id}/connect",
        json={"scope_ids": [AWS_ACCOUNT_ID]},
    )

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["provider"] == "AWS"
    assert body["status"] == "connected"
    assert body["linked_scope_ids"] == [AWS_ACCOUNT_ID]
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# AWS connect mirrors the account into the subscriptions repo so the
# timer-driven ScanPipeline picks it up automatically.
# ---------------------------------------------------------------------------


def test_v1_aws_connect_mirrors_account_into_subscriptions_repo() -> None:
    """Connecting an AWS account must write a SubscriptionRecord(provider=AWS)
    keyed on the 12-digit account id, so the next scheduled scan tick
    picks it up via the existing _list_enabled_subscriptions path."""
    import asyncio
    from cloudguardiq.core.enums import CloudProvider as CoreProvider

    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()
    res_create = client.post(
        "/v1/onboarding/sessions",
        json={
            "provider": "AWS",
            "display_name": "Prod AWS",
            "target_scope": {
                "account_id": AWS_ACCOUNT_ID,
                "region": "us-west-2",
            },
        },
    )
    assert res_create.status_code == 201, res_create.text
    session_id = res_create.json()["session_id"]
    client.post(f"/v1/onboarding/sessions/{session_id}/verify")
    res = client.post(
        f"/v1/onboarding/sessions/{session_id}/connect",
        json={"scope_ids": [AWS_ACCOUNT_ID]},
    )
    assert res.status_code == 200, res.text

    repo = subs_module._get_repo()
    stored = asyncio.run(repo.get(HOME_TID, AWS_ACCOUNT_ID))
    assert stored is not None
    assert stored.provider is CoreProvider.AWS
    assert stored.aws_account_id == AWS_ACCOUNT_ID
    assert stored.aws_region == "us-west-2"

    app.dependency_overrides.clear()


def test_v1_aws_create_rejects_bad_region() -> None:
    _wire()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=HOME_TID, oid="oid-1",
    )
    client = _client()
    res = client.post(
        "/v1/onboarding/sessions",
        json={
            "provider": "AWS",
            "display_name": "Prod AWS",
            "target_scope": {
                "account_id": AWS_ACCOUNT_ID,
                "region": "USWEST2",
            },
        },
    )
    assert res.status_code == 400
    assert res.json()["detail"]["error_code"] == "invalid_target_scope"
    app.dependency_overrides.clear()
