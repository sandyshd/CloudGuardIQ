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


def test_pro_cap_is_3() -> None:
    """PRO plan caps subscriptions at 3 (from plan catalog)."""
    _wire(tier=SubscriptionTier.PRO)
    client = _client()
    for i in range(3):
        sid = f"{i:08d}-1111-1111-1111-111111111111"
        r = client.post("/subscriptions", json={"subscription_id": sid})
        assert r.status_code == 201, f"add #{i} failed: {r.text}"
    r = client.post(
        "/subscriptions",
        json={"subscription_id": "99999999-9999-9999-9999-999999999999"},
    )
    assert r.status_code == 402
    assert r.json()["detail"]["cap"] == 3


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


def test_remove_then_relink_restores_record_and_bypasses_cap() -> None:
    """Soft-delete + relink restores the original record without consuming
    a Free-tier cap slot a second time."""
    _wire(tier=SubscriptionTier.FREE)
    client = _client()
    sid = "11111111-1111-1111-1111-111111111111"

    # 1. Add (uses the only Free slot)
    r = client.post(
        "/subscriptions",
        json={"subscription_id": sid, "display_name": "Prod"},
    )
    assert r.status_code == 201

    # 2. Remove (soft delete)
    r = client.delete(f"/subscriptions/{sid}")
    assert r.status_code == 204

    # 3. Listing hides Removed records
    r = client.get("/subscriptions")
    assert r.status_code == 200
    assert r.json() == []

    # 4. Re-add: must succeed without 402 because the Removed slot is freed,
    #    and the response should reflect the restored row (state=Enabled).
    r = client.post(
        "/subscriptions",
        json={"subscription_id": sid, "display_name": "Prod restored"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["state"] == "Enabled"
    assert body["display_name"] == "Prod restored"


def test_add_subscription_blocked_when_access_probe_denies(monkeypatch) -> None:
    """When CloudGuardIQ has no Reader RBAC, POST /subscriptions returns 400."""
    from cloudguardiq.adapters.access_probe import AccessProbeResult
    from cloudguardiq.api import subscriptions as subs_module

    _wire(tier=SubscriptionTier.FREE)

    async def deny(_subscription_id: str) -> AccessProbeResult:
        return AccessProbeResult(
            ok=False, resource_count=0,
            error="AuthorizationFailed: principal does not have access",
        )

    subs_module.set_access_probe(deny)
    monkeypatch.setattr(
        "cloudguardiq.api.subscriptions._get_settings",
        lambda: type("S", (), {"auth_disabled": False})(),
    )
    try:
        client = _client()
        r = client.post(
            "/subscriptions",
            json={
                "subscription_id": "11111111-1111-1111-1111-111111111111",
                "display_name": "Prod",
            },
        )
        assert r.status_code == 400, r.text
        detail = r.json()["detail"]
        assert detail["error"] == "access_denied"
        assert "az role assignment create" in detail["az_command"]
        assert "11111111-1111-1111-1111-111111111111" in detail["az_command"]
    finally:
        subs_module.set_access_probe(None)


def test_add_subscription_succeeds_when_access_probe_passes(monkeypatch) -> None:
    """When the probe returns ok=True the route stores the subscription."""
    from cloudguardiq.adapters.access_probe import AccessProbeResult
    from cloudguardiq.api import subscriptions as subs_module

    _wire(tier=SubscriptionTier.FREE)

    async def allow(_subscription_id: str) -> AccessProbeResult:
        return AccessProbeResult(ok=True, resource_count=42)

    subs_module.set_access_probe(allow)
    monkeypatch.setattr(
        "cloudguardiq.api.subscriptions._get_settings",
        lambda: type("S", (), {"auth_disabled": False})(),
    )
    try:
        client = _client()
        r = client.post(
            "/subscriptions",
            json={
                "subscription_id": "22222222-2222-2222-2222-222222222222",
                "display_name": "Staging",
            },
        )
        assert r.status_code == 201, r.text
    finally:
        subs_module.set_access_probe(None)


def test_onboarding_info_endpoint() -> None:
    client = _client()
    r = client.get("/onboarding/info")
    assert r.status_code == 200
    body = r.json()
    assert "azure_principal_id" in body
    assert body["role"] == "Reader"
    assert "az role assignment create" in body["az_command_template"]



def test_add_rejects_aws_account_id() -> None:
    # AWS 12-digit account IDs must return 400 unsupported_provider.
    _wire()
    client = _client()
    r = client.post(
        "/subscriptions",
        json={"subscription_id": "123456789012", "display_name": "aws-prod"},
    )
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["detail"]["error"] == "unsupported_provider"
    assert body["detail"]["provider"] == "aws"


def test_add_rejects_gcp_project_id() -> None:
    # GCP project IDs must return 400 unsupported_provider.
    _wire()
    client = _client()
    r = client.post(
        "/subscriptions",
        json={"subscription_id": "my-prod-project-42", "display_name": "gcp"},
    )
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["detail"]["error"] == "unsupported_provider"
    assert body["detail"]["provider"] == "gcp"


def test_add_rejects_garbage_with_invalid_id_error() -> None:
    # Non-cloud junk strings must return 400 invalid_subscription_id.
    _wire()
    client = _client()
    r = client.post(
        "/subscriptions",
        json={"subscription_id": "not_a_guid_at_all", "display_name": "x"},
    )
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["detail"]["error"] == "invalid_subscription_id"


# ---------------------------------------------------------------------------
# Onboarding template URL normalization
# ---------------------------------------------------------------------------


def test_normalize_template_uri_rewrites_github_blob() -> None:
    """github.com/<o>/<r>/blob/<ref>/<path> -> raw.githubusercontent.com/..."""
    from cloudguardiq.api.subscriptions import _normalize_template_uri
    src = "https://github.com/sandyshd/CloudGuardIQ/blob/development/infra/templates/cloudguardiq-reader.json"
    expected = "https://raw.githubusercontent.com/sandyshd/CloudGuardIQ/development/infra/templates/cloudguardiq-reader.json"
    assert _normalize_template_uri(src) == expected


def test_normalize_template_uri_passthrough_raw() -> None:
    """raw.githubusercontent.com URLs are returned unchanged."""
    from cloudguardiq.api.subscriptions import _normalize_template_uri
    raw = "https://raw.githubusercontent.com/sandyshd/CloudGuardIQ/main/infra/templates/cloudguardiq-reader.json"
    assert _normalize_template_uri(raw) == raw


def test_normalize_template_uri_passthrough_other() -> None:
    """Non-GitHub URLs (storage, CDN) are returned unchanged."""
    from cloudguardiq.api.subscriptions import _normalize_template_uri
    sa = "https://cguardiqassets.blob.core.windows.net/templates/reader.json"
    assert _normalize_template_uri(sa) == sa


def test_normalize_template_uri_empty() -> None:
    """Empty input returns empty (callers handle the unconfigured case)."""
    from cloudguardiq.api.subscriptions import _normalize_template_uri
    assert _normalize_template_uri("") == ""


def test_build_deploy_url_uses_normalized_uri_via_get_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """/onboarding-template rewrites a /blob/ URI before encoding."""
    blob = "https://github.com/sandyshd/CloudGuardIQ/blob/development/infra/templates/cloudguardiq-reader.json"
    raw = "https://raw.githubusercontent.com/sandyshd/CloudGuardIQ/development/infra/templates/cloudguardiq-reader.json"

    client = TestClient(app)
    _wire()

    # Inject a settings object that returns the misconfigured /blob/ URL.
    settings = Settings()
    settings.onboarding_template_uri = blob
    monkeypatch.setattr(subs_module, "_get_settings", lambda: settings)

    r = client.get("/subscriptions/onboarding-template?tenant_id=tenant-A")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["template_uri"] == raw
    # quoted raw URL must appear in deploy_url
    from urllib.parse import quote
    assert quote(raw, safe="") in body["deploy_url"]
    assert "#create/Microsoft.Template/uri/" in body["deploy_url"]
