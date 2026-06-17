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
from cloudguardiq.subscriptions.repository import (
    SubscriptionRecord,
    SubscriptionsRepository,
)


def _wire(tier: SubscriptionTier | None = None) -> None:
    """Wire the subscriptions module with in-memory repos.

    Called *after* the TestClient is constructed because TestClient's
    lifespan hook re-configures the module with the real Cosmos bootstrap
    repos and would otherwise clobber the in-memory wiring.
    """
    # Enable Stripe-billing mode so tenants without a record default to
    # FREE and the per-tier caps are enforced (otherwise the Stripe-free
    # default is ENTERPRISE = unlimited).
    settings = Settings(billing_stripe_enabled=True)
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


def test_normalize_template_uri_strips_wrapping_quotes() -> None:
    """Wrapping quotes/whitespace (a common misconfiguration in CI secrets or
    .env files like ``ONBOARDING_TEMPLATE_URI='https://.../json'``) must be
    stripped so the Portal Deploy-to-Azure link does not end with a trailing
    URL-encoded ``%27`` and fail to download the template."""
    from cloudguardiq.api.subscriptions import _normalize_template_uri
    raw = "https://raw.githubusercontent.com/sandyshd/CloudGuardIQ/development/infra/templates/cloudguardiq-reader.json"
    assert _normalize_template_uri(f"'{raw}'") == raw
    assert _normalize_template_uri(f'"{raw}"') == raw
    assert _normalize_template_uri(f"  {raw}\n") == raw
    blob = "https://github.com/sandyshd/CloudGuardIQ/blob/development/infra/templates/cloudguardiq-reader.json"
    assert _normalize_template_uri(f"'{blob}'") == raw


# ---------------------------------------------------------------------------
# Bundled ARM template served from the API (Option 1: private-repo-safe)
# ---------------------------------------------------------------------------


def test_resolve_template_uri_prefers_explicit() -> None:
    """An explicit onboarding_template_uri wins over the auto-default."""
    from cloudguardiq.api.subscriptions import _resolve_template_uri
    s = Settings()
    s.onboarding_template_uri = (
        "https://cdn.example.com/templates/cloudguardiq-reader.json"
    )
    s.public_api_base_url = "https://api.example.com"
    assert _resolve_template_uri(s) == (
        "https://cdn.example.com/templates/cloudguardiq-reader.json"
    )


def test_resolve_template_uri_falls_back_to_bundled_endpoint() -> None:
    """When no explicit URI is set, build the URL from public_api_base_url."""
    from cloudguardiq.api.subscriptions import _resolve_template_uri
    s = Settings()
    s.onboarding_template_uri = ""
    s.public_api_base_url = "https://api.example.com/"
    assert _resolve_template_uri(s) == (
        "https://api.example.com/subscriptions/onboarding-template.json"
    )


def test_resolve_template_uri_empty_when_unconfigured() -> None:
    """Neither URI nor base URL set -> empty (callers raise 503)."""
    from cloudguardiq.api.subscriptions import _resolve_template_uri
    s = Settings()
    s.onboarding_template_uri = ""
    s.public_api_base_url = ""
    assert _resolve_template_uri(s) == ""


def test_resolve_template_uri_strips_wrapping_quotes_on_base_url() -> None:
    """A misconfigured base URL with literal quotes must not produce a
    URL ending in ``%27`` or stray whitespace."""
    from cloudguardiq.api.subscriptions import _resolve_template_uri
    s = Settings()
    s.onboarding_template_uri = ""
    s.public_api_base_url = "'https://api.example.com'"
    assert _resolve_template_uri(s) == (
        "https://api.example.com/subscriptions/onboarding-template.json"
    )


def test_onboarding_template_json_route_serves_valid_arm_template() -> None:
    """The anonymous route returns the bundled ARM template body so the
    Azure Portal Deploy-to-Azure blade can fetch it without auth."""
    import json
    _wire()
    client = _client()
    # Route is unauthenticated by design -- clear the override to confirm.
    app.dependency_overrides.clear()
    try:
        r = client.get("/subscriptions/onboarding-template.json")
    finally:
        app.dependency_overrides[verify_token] = lambda: TokenPayload(
            sub="user-1", tid="tenant-A",
        )
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/json")
    assert r.headers.get("access-control-allow-origin") == "*"
    body = json.loads(r.content)
    assert body["$schema"].startswith(
        "https://schema.management.azure.com/"
    )
    assert body["resources"][0]["type"] == (
        "Microsoft.Authorization/roleAssignments"
    )
    assert "cloudGuardIQPrincipalId" in body["parameters"]



def test_onboarding_template_includes_optin_policy_assignment() -> None:
    """The bundled template carries an opt-in policy-initiative assignment.

    The Reader role assignment must remain resources[0] (Deploy blade and the
    existing test rely on it); the policy assignment is a conditional copy loop
    that produces nothing when policySetDefinitionIds is empty (the default).
    """
    import json

    _wire()
    client = _client()
    app.dependency_overrides.clear()
    try:
        r = client.get("/subscriptions/onboarding-template.json")
    finally:
        app.dependency_overrides[verify_token] = lambda: TokenPayload(
            sub="user-1", tid="tenant-A",
        )
    assert r.status_code == 200, r.text
    body = json.loads(r.content)

    # Reader stays first so the existing contract holds.
    assert body["resources"][0]["type"] == (
        "Microsoft.Authorization/roleAssignments"
    )

    # Opt-in initiative assignment is present, conditional, and a copy loop.
    policy = next(
        res
        for res in body["resources"]
        if res["type"] == "Microsoft.Authorization/policyAssignments"
    )
    assert "condition" in policy
    assert policy["copy"]["count"] == (
        "[length(parameters('policySetDefinitionIds'))]"
    )
    assert policy["properties"]["enforcementMode"] == "Default"

    # Default is empty => Reader-only behaviour is unchanged.
    param = body["parameters"]["policySetDefinitionIds"]
    assert param["type"] == "array"
    assert param["defaultValue"] == []
    assert body["outputs"]["assignedInitiativeCount"]["type"] == "int"

def test_onboarding_template_endpoint_uses_bundled_url_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /subscriptions/onboarding-template returns the API-hosted URL
    when CLOUDGUARDIQ_ONBOARDING_TEMPLATE_URI is empty but
    CLOUDGUARDIQ_PUBLIC_API_BASE_URL is configured."""
    from urllib.parse import quote
    _wire()
    settings = Settings()
    settings.onboarding_template_uri = ""
    settings.public_api_base_url = "https://api.example.com"
    monkeypatch.setattr(subs_module, "_get_settings", lambda: settings)

    client = _client()
    r = client.get("/subscriptions/onboarding-template?tenant_id=tenant-A")
    assert r.status_code == 200, r.text
    body = r.json()
    expected = (
        "https://api.example.com/subscriptions/onboarding-template.json"
    )
    assert body["template_uri"] == expected
    assert quote(expected, safe="") in body["deploy_url"]


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


def test_operator_enrolled_subscription_is_visible_to_customer_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operator enrollment persists under customer tenant ownership."""
    _wire()
    client = _client()

    # Keep the flow focused on ownership semantics, not consent wiring.
    monkeypatch.setattr(
        "cloudguardiq.api.subscriptions._get_settings",
        lambda: type("S", (), {"auth_disabled": True})(),
    )

    sid = "aaaaaaaa-1111-1111-1111-111111111111"
    r = client.post(
        "/subscriptions",
        json={
            "subscription_id": sid,
            "customer_tenant_id": "tenant-b",
            "display_name": "Customer Prod",
        },
    )
    assert r.status_code == 201, r.text

    # Operator tenant should not own or list customer-owned rows.
    r = client.get("/subscriptions")
    assert r.status_code == 200
    assert r.json() == []

    # Customer tenant sees the linked subscription after login.
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="customer-user", tid="tenant-b",
    )
    r = client.get("/subscriptions")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert body[0]["subscription_id"] == sid


def test_customer_list_claims_legacy_operator_owned_subscription() -> None:
    """Legacy rows keyed by operator tenant are materialized for customer."""
    _wire()
    client = _client()

    sid = "bbbbbbbb-2222-2222-2222-222222222222"
    repo = subs_module._repository
    assert repo is not None
    asyncio.run(repo.upsert(SubscriptionRecord(
        tenant_id="tenant-A",
        subscription_id=sid,
        customer_tenant_id="tenant-b",
        display_name="Legacy linked",
    )))

    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="customer-user", tid="tenant-b",
    )
    r = client.get("/subscriptions")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert body[0]["subscription_id"] == sid

    # Claimed row is now customer-owned so lifecycle operations work.
    r = client.delete(f"/subscriptions/{sid}")
    assert r.status_code == 204

def test_onboarding_parameters_returns_arm_json() -> None:
    """Anonymous endpoint returns ARM parameters JSON for a valid GUID."""
    client = TestClient(app)
    pid = "c237acc3-b7d8-4bb9-ad58-f0343ff8f331"
    r = client.get(f"/subscriptions/onboarding-parameters/{pid}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["contentVersion"] == "1.0.0.0"
    assert body["parameters"]["cloudGuardIQPrincipalId"]["value"] == pid
    assert "deploymentParameters.json" in body["$schema"]


def test_onboarding_parameters_rejects_non_guid() -> None:
    """Endpoint refuses non-GUID input to avoid emitting junk JSON."""
    client = TestClient(app)
    r = client.get("/subscriptions/onboarding-parameters/not-a-guid")
    assert r.status_code == 400


def test_onboarding_template_emits_parameters_uri_when_base_url_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """parameters_uri stays available for the manual CLI flow; the deploy
    URL prefills parameters via template defaults, not /uriParameters/."""
    client = TestClient(app)
    _wire()

    raw = "https://raw.githubusercontent.com/sandyshd/CloudGuardIQ/development/infra/templates/cloudguardiq-reader.json"
    pid = "c237acc3-b7d8-4bb9-ad58-f0343ff8f331"

    settings = Settings()
    settings.onboarding_template_uri = raw
    settings.public_api_base_url = "https://api.example.com"
    settings.azure_principal_id = pid
    monkeypatch.setattr(subs_module, "_get_settings", lambda: settings)

    r = client.get("/subscriptions/onboarding-template?tenant_id=tenant-A")
    assert r.status_code == 200, r.text
    body = r.json()
    expected_params = f"https://api.example.com/subscriptions/onboarding-parameters/{pid}"
    assert body["parameters_uri"] == expected_params
    # The portal ignores remote parameter files, so the deploy URL
    # prefills via template defaults (principal_id query), not
    # /uriParameters/.
    assert "/uriParameters/" not in body["deploy_url"]
    assert "principal_id" in body["deploy_url"]
    assert pid in body["deploy_url"]


def test_onboarding_template_omits_parameters_uri_when_base_url_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without public_api_base_url, parameters_uri is empty.

    deploy_url must not include the /uriParameters/ segment.
    """
    client = TestClient(app)
    _wire()

    raw = "https://raw.githubusercontent.com/sandyshd/CloudGuardIQ/development/infra/templates/cloudguardiq-reader.json"
    settings = Settings()
    settings.onboarding_template_uri = raw
    settings.public_api_base_url = ""
    monkeypatch.setattr(subs_module, "_get_settings", lambda: settings)

    r = client.get("/subscriptions/onboarding-template?tenant_id=tenant-A")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["parameters_uri"] == ""
    assert "/uriParameters/" not in body["deploy_url"]
# ---------------------------------------------------------------------------
# Automatic latest-initiative discovery -> Deploy-to-Azure parameter wiring
# ---------------------------------------------------------------------------

_CIS_AZURE_GUID = "06f19060-9e68-4070-92ca-f15cc126059e"
_POLICY_SET_PREFIX = (
    "/providers/Microsoft.Authorization/policySetDefinitions/"
)


def test_onboarding_parameters_includes_initiatives_when_requested() -> None:
    """initiatives query param adds policySetDefinitionIds to the ARM params."""
    client = TestClient(app)
    pid = "c237acc3-b7d8-4bb9-ad58-f0343ff8f331"
    r = client.get(
        f"/subscriptions/onboarding-parameters/{pid}"
        f"?initiatives={_CIS_AZURE_GUID}"
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["parameters"]["cloudGuardIQPrincipalId"]["value"] == pid
    ids = body["parameters"]["policySetDefinitionIds"]["value"]
    assert ids == [_POLICY_SET_PREFIX + _CIS_AZURE_GUID]


def test_onboarding_parameters_filters_invalid_initiative_guids() -> None:
    """Non-GUID initiative tokens are dropped; valid ones are kept."""
    client = TestClient(app)
    pid = "c237acc3-b7d8-4bb9-ad58-f0343ff8f331"
    r = client.get(
        f"/subscriptions/onboarding-parameters/{pid}"
        f"?initiatives=not-a-guid,{_CIS_AZURE_GUID}"
    )
    assert r.status_code == 200, r.text
    body = r.json()
    ids = body["parameters"]["policySetDefinitionIds"]["value"]
    assert ids == [_POLICY_SET_PREFIX + _CIS_AZURE_GUID]


def test_onboarding_parameters_omits_initiatives_when_none_valid() -> None:
    """No policySetDefinitionIds key when no valid GUID supplied."""
    client = TestClient(app)
    pid = "c237acc3-b7d8-4bb9-ad58-f0343ff8f331"
    r = client.get(
        f"/subscriptions/onboarding-parameters/{pid}?initiatives=nope"
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "policySetDefinitionIds" not in body["parameters"]


def test_onboarding_template_assign_frameworks_populates_initiatives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """assign_frameworks auto-populates the deploy parameters with latest GUIDs."""
    from urllib.parse import quote

    client = TestClient(app)
    _wire()

    raw = "https://raw.githubusercontent.com/sandyshd/CloudGuardIQ/development/infra/templates/cloudguardiq-reader.json"
    pid = "c237acc3-b7d8-4bb9-ad58-f0343ff8f331"
    settings = Settings()
    settings.onboarding_template_uri = raw
    settings.public_api_base_url = "https://api.example.com"
    settings.azure_principal_id = pid
    monkeypatch.setattr(subs_module, "_get_settings", lambda: settings)

    r = client.get(
        "/subscriptions/onboarding-template"
        "?tenant_id=tenant-A&assign_frameworks=CIS_AZURE"
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert f"initiatives={_CIS_AZURE_GUID}" in body["parameters_uri"]
    assert quote(f"initiatives={_CIS_AZURE_GUID}", safe="") in body["deploy_url"]
    assigned = body["assigned_initiatives"]
    assert len(assigned) == 1
    assert assigned[0]["framework_id"] == "CIS_AZURE"
    assert assigned[0]["source"] == "static"


def test_onboarding_template_default_has_no_assigned_initiatives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without assign_frameworks the deploy stays Reader-only (back-compat)."""
    client = TestClient(app)
    _wire()

    raw = "https://raw.githubusercontent.com/sandyshd/CloudGuardIQ/development/infra/templates/cloudguardiq-reader.json"
    pid = "c237acc3-b7d8-4bb9-ad58-f0343ff8f331"
    settings = Settings()
    settings.onboarding_template_uri = raw
    settings.public_api_base_url = "https://api.example.com"
    settings.azure_principal_id = pid
    monkeypatch.setattr(subs_module, "_get_settings", lambda: settings)

    r = client.get("/subscriptions/onboarding-template?tenant_id=tenant-A")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "initiatives=" not in body["parameters_uri"]
    assert body["assigned_initiatives"] == []


def test_available_initiatives_returns_static_fallback() -> None:
    """available-initiatives returns the pinned map when discovery is unavailable."""
    client = TestClient(app)
    _wire()
    r = client.get("/subscriptions/available-initiatives?tenant_id=tenant-A")
    assert r.status_code == 200, r.text
    body = r.json()
    frameworks = {i["framework_id"] for i in body["initiatives"]}
    assert "CIS_AZURE" in frameworks
    cis = next(i for i in body["initiatives"] if i["framework_id"] == "CIS_AZURE")
    assert cis["definition_id"].endswith(_CIS_AZURE_GUID)
    assert cis["source"] == "static"


def test_onboarding_template_json_prefills_defaults_from_query() -> None:
    """Query params inject defaultValue so the Deploy blade opens
    pre-filled (the portal does not fetch remote parameter files)."""
    import json

    _wire()
    client = _client()
    pid = "c237acc3-b7d8-4bb9-ad58-f0343ff8f331"
    app.dependency_overrides.clear()
    try:
        r = client.get(
            "/subscriptions/onboarding-template.json"
            f"?principal_id={pid}&initiatives={_CIS_AZURE_GUID}"
        )
    finally:
        app.dependency_overrides[verify_token] = lambda: TokenPayload(
            sub="user-1", tid="tenant-A",
        )
    assert r.status_code == 200, r.text
    body = json.loads(r.content)
    params = body["parameters"]
    assert params["cloudGuardIQPrincipalId"]["defaultValue"] == pid
    assert params["policySetDefinitionIds"]["defaultValue"] == [
        _POLICY_SET_PREFIX + _CIS_AZURE_GUID
    ]
