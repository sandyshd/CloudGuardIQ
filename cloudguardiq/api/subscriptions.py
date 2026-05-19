"""CloudGuardIQ -- Subscription management FastAPI routes (Phase 2).

Tenants manage their linked Azure subscriptions through this router. Tier
caps are enforced here using the JWT ``tid`` claim.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, field_validator

from cloudguardiq.adapters.access_probe import (
    AccessProbeResult,
    probe_subscription_access,
)
from cloudguardiq.api.auth import TokenPayload, get_tenant_id, verify_token
from cloudguardiq.api.onboarding import OnboardingInfo
from cloudguardiq.billing.plans import get_plan
from cloudguardiq.billing.repository import BillingRepository
from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import SubscriptionTier
from cloudguardiq.subscriptions.repository import (
    SubscriptionRecord,
    SubscriptionsRepository,
)
from cloudguardiq.tenants.consent_repository import (
    TenantConsent,
    TenantConsentRepository,
)

logger = logging.getLogger(__name__)

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# AWS account IDs are exactly 12 digits.
_AWS_ACCOUNT_RE = re.compile(r"^\d{12}$")

# GCP project IDs: 6-30 chars, must start with a lowercase letter, end
# with a letter or digit, and contain at least one hyphen to avoid
# eating short alphanumeric typos.
_GCP_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


def _detect_provider(value: str) -> str:
    """Return ``azure`` | ``aws`` | ``gcp`` | ``unknown`` for an id string.

    Short-term guard for Phase 6.10. The full Phase 6 implementation
    will replace this with a ``CloudProvider`` discriminator on the
    request model.
    """
    if _GUID_RE.match(value):
        return "azure"
    if _AWS_ACCOUNT_RE.match(value):
        return "aws"
    if _GCP_PROJECT_RE.match(value) and "-" in value:
        return "gcp"
    return "unknown"


# ---------------------------------------------------------------------------
# Wire-format models
# ---------------------------------------------------------------------------


class SubscriptionResponse(BaseModel):
    """Wire shape returned to the frontend."""

    subscription_id: str
    display_name: str = ""
    state: str = "Enabled"

    @classmethod
    def from_record(cls, rec: SubscriptionRecord) -> SubscriptionResponse:
        """Build a response payload from a stored record."""
        return cls(
            subscription_id=rec.subscription_id,
            display_name=rec.display_name or rec.subscription_id,
            state=rec.state,
        )


class AddSubscriptionRequest(BaseModel):
    """Body for ``POST /subscriptions``.

    ``subscription_id`` is validated only loosely at the Pydantic layer
    so the route handler can return tailored 400 responses for non-Azure
    cloud identifiers. Pydantic-level rejection would surface as a
    generic 422 which hides *why* the id was rejected.
    """

    subscription_id: str = Field(..., min_length=1, max_length=64)
    display_name: str = ""
    # Optional: the Azure tenant that owns this subscription. When the
    # caller does not supply it we default to their JWT ``tid`` claim
    # (single-tenant onboarding). For Phase 3 cross-tenant flows the
    # frontend passes the customer's Entra tenant id explicitly.
    customer_tenant_id: str = ""

    @field_validator("subscription_id")
    @classmethod
    def _normalize(cls, v: str) -> str:
        return v.strip().lower()


class PatchSubscriptionRequest(BaseModel):
    """Body for ``PATCH /subscriptions/{id}``."""

    display_name: str | None = None
    state: str | None = None

    @field_validator("state")
    @classmethod
    def _check_state(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if v not in {"Enabled", "Disabled"}:
            raise ValueError("state must be 'Enabled' or 'Disabled'")
        return v


# ---------------------------------------------------------------------------
# Module-level wiring (configured from app startup)
# ---------------------------------------------------------------------------


_repository: SubscriptionsRepository | None = None
_billing_repo: BillingRepository | None = None
_settings: Settings | None = None
_consent_repo: TenantConsentRepository | None = None
# Factory for per-customer-tenant Azure credentials. Wired only when
# Phase 3 cross-tenant credentials (cert or secret) are configured;
# ``None`` falls back to the local DefaultAzureCredential.
_credential_factory: object | None = None

# Tests inject a stub probe via subscriptions.set_access_probe(); production
# leaves it None and uses the default Resource Graph probe.
from collections.abc import Awaitable, Callable  # noqa: E402

_AccessProbe = Callable[[str], Awaitable[AccessProbeResult]]
_probe_override: _AccessProbe | None = None


def set_access_probe(probe: _AccessProbe | None) -> None:
    """Install a custom access probe (tests only)."""
    global _probe_override  # noqa: PLW0603
    _probe_override = probe


def configure(
    *,
    repository: SubscriptionsRepository,
    billing_repository: BillingRepository,
    settings: Settings,
    consent_repository: TenantConsentRepository | None = None,
    credential_factory: object | None = None,
) -> None:
    """Wire dependencies from the application startup hook.

    *consent_repository* and *credential_factory* are Phase 3 additions
    used to enforce admin consent and to authenticate against the
    customer's Entra tenant when probing cross-tenant subscriptions.
    Both are optional so single-tenant deployments keep working.
    """
    global _repository, _billing_repo, _settings  # noqa: PLW0603
    global _consent_repo, _credential_factory  # noqa: PLW0603
    _repository = repository
    _billing_repo = billing_repository
    _settings = settings
    _consent_repo = consent_repository
    _credential_factory = credential_factory


def _get_consent_repo() -> TenantConsentRepository | None:
    """Return the configured consent repository or ``None``."""
    return _consent_repo


def _get_repo() -> SubscriptionsRepository:
    if _repository is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Subscriptions repository not configured",
        )
    return _repository


def _get_billing() -> BillingRepository:
    if _billing_repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing repository not configured",
        )
    return _billing_repo


def _get_settings() -> Settings:
    if _settings is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Settings not configured",
        )
    return _settings


def _cap_for_tier(settings: Settings, tier: SubscriptionTier) -> int:  # noqa: ARG001
    """Return the subscription cap for *tier* (-1 means unlimited).

    Sourced from the plan catalog (cloudguardiq.billing.plans) — the single
    cloud-agnostic source of truth for tier limits. The *settings* parameter
    is retained for call-site backward compatibility.
    """
    return get_plan(tier).max_subscriptions


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


async def _run_access_probe(
    subscription_id: str, *, customer_tenant_id: str = "",
) -> AccessProbeResult | None:
    """Run the access probe (test override or default Resource Graph).

    When a *customer_tenant_id* is supplied and the cross-tenant
    credential factory is wired, the probe authenticates against
    that customer's Entra tenant -- this is the Phase 3 cross-tenant
    path. Otherwise it falls back to ``DefaultAzureCredential`` for
    the operator's own tenant.

    Returns ``None`` when the probe cannot be executed (no Azure
    credential available, e.g. local dev without ``az login``); the
    caller treats ``None`` as a soft-pass so contributors are not
    blocked offline.
    """
    if _probe_override is not None:
        return await _probe_override(subscription_id)

    if customer_tenant_id and _credential_factory is not None:
        try:
            credential = _credential_factory.for_tenant(customer_tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Customer credential build failed for tenant=%s: %s",
                customer_tenant_id, exc,
            )
            return None
        return await probe_subscription_access(credential, subscription_id)

    try:
        from azure.identity import DefaultAzureCredential
    except Exception as exc:  # noqa: BLE001
        logger.warning("azure-identity unavailable; skipping probe: %s", exc)
        return None
    try:
        credential = DefaultAzureCredential()
    except Exception as exc:  # noqa: BLE001
        logger.warning("DefaultAzureCredential init failed: %s", exc)
        return None
    return await probe_subscription_access(credential, subscription_id)


router = APIRouter(prefix="/subscriptions", tags=["subscriptions"])
_auth = Depends(verify_token)


@router.get("", response_model=list[SubscriptionResponse])
async def list_subscriptions(
    user: TokenPayload = _auth,
) -> list[SubscriptionResponse]:
    """Return the caller tenant's linked Azure subscriptions."""
    tenant_id = get_tenant_id(user)
    repo = _get_repo()
    records = await repo.list(tenant_id)
    return [SubscriptionResponse.from_record(r) for r in records]


@router.post(
    "", response_model=SubscriptionResponse, status_code=status.HTTP_201_CREATED
)
async def add_subscription(
    body: AddSubscriptionRequest,
    user: TokenPayload = _auth,
) -> Any:
    """Link a new Azure subscription to the caller's tenant.

    Enforces the per-tier cap. The route returns ``402 upgrade_required``
    when the tenant is at its plan limit.
    """
    tenant_id = get_tenant_id(user)
    customer_tid = (body.customer_tenant_id or tenant_id).strip().lower()
    repo = _get_repo()
    billing = _get_billing()
    settings = _get_settings()

    # Cross-tenant guard (Phase 3.4): when the customer tenant differs
    # from the caller's tenant we must have a recorded admin consent
    # before we can issue an Azure access probe against it. Without
    # this guard a malicious caller could try to brute-force tenant
    # ids by triggering access probes through us.
    if customer_tid != tenant_id.lower() and not settings.auth_disabled:
        consent_repo = _get_consent_repo()
        if consent_repo is None or not await consent_repo.has_active_consent(
            customer_tid,
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "consent_required",
                    "customer_tenant_id": customer_tid,
                    "message": (
                        "Admin consent has not been recorded for this "
                        "customer tenant. Open the consent URL from "
                        "GET /subscriptions/consent-url first."
                    ),
                },
            )

    # Phase 6.10 short-term guard: reject AWS / GCP identifiers with a
    # clear roadmap message. Without this they would fall through to the
    # access probe and fail with a confusing Azure-flavoured error.
    provider = _detect_provider(body.subscription_id)
    if provider in ("aws", "gcp"):
        logger.info(
            "Rejected non-Azure subscription_id tenant=%s provider=%s",
            tenant_id, provider,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "unsupported_provider",
                "provider": provider,
                "message": (
                    f"{provider.upper()} accounts are on the CloudGuardIQ "
                    "roadmap (Phase 6) but are not yet supported. Today "
                    "you can link Azure subscriptions only."
                ),
            },
        )
    if provider != "azure":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_subscription_id",
                "message": (
                    "subscription_id must be an Azure subscription GUID "
                    "(8-4-4-4-12 hex)."
                ),
            },
        )

    record = await billing.get(tenant_id)
    tier = record.tier if record else SubscriptionTier.FREE
    cap = _cap_for_tier(settings, tier)

    # Verify CloudGuardIQ has Reader access on this subscription before
    # storing it. Without RBAC the scan would silently return 0 findings,
    # which is a confusing onboarding experience. We return 400 with the
    # principal id and a copy-pasteable az command so the user can fix
    # the grant and retry.
    settings_obj = _get_settings()
    if not settings_obj.auth_disabled:
        probe_result = await _run_access_probe(
            body.subscription_id, customer_tenant_id=customer_tid,
        )
        if probe_result is not None and not probe_result.ok:
            info = OnboardingInfo.build()
            cmd = (
                "az role assignment create "
                f"--assignee {info.azure_principal_id} "
                "--role Reader "
                f"--scope /subscriptions/{body.subscription_id}"
            )
            logger.info(
                "Access probe denied for tenant=%s sub=%s: %s",
                tenant_id, body.subscription_id, probe_result.error,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "access_denied",
                    "message": (
                        "CloudGuardIQ does not have Reader access on this "
                        "subscription. Run the command below from a shell "
                        "signed in as a subscription Owner, then click Add again."
                    ),
                    "azure_principal_id": info.azure_principal_id,
                    "role": "Reader",
                    "az_command": cmd,
                    "azure_error": probe_result.error,
                },
            )

    # Soft-delete restore: if the GUID was previously Removed, bring it
    # back so the tenant recovers its historical findings without paying
    # the tier-cap cost twice.
    existing = await repo.get(tenant_id, body.subscription_id)
    if existing is not None and existing.state == "Removed":
        existing.state = "Enabled"
        existing.removed_at = None
        if body.display_name:
            existing.display_name = body.display_name
        restored = await repo.upsert(existing)
        logger.info(
            "Restored soft-deleted subscription tenant=%s sub=%s",
            tenant_id, body.subscription_id,
        )
        return SubscriptionResponse.from_record(restored)

    current = await repo.count(tenant_id)
    if cap >= 0 and current >= cap:
        logger.info(
            "Tier cap reached: tenant=%s tier=%s current=%d cap=%d",
            tenant_id, tier.value, current, cap,
        )
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "upgrade_required",
                "current_tier": tier.value.lower(),
                "limit": "subscriptions",
                "cap": cap,
                "current": current,
            },
        )

    rec = SubscriptionRecord(
        tenant_id=tenant_id,
        subscription_id=body.subscription_id,
        display_name=body.display_name or body.subscription_id,
        customer_tenant_id=customer_tid,
    )
    saved = await repo.upsert(rec)
    return SubscriptionResponse.from_record(saved)


@router.patch(
    "/{subscription_id}", response_model=SubscriptionResponse,
)
async def patch_subscription(
    subscription_id: str,
    body: PatchSubscriptionRequest,
    user: TokenPayload = _auth,
) -> Any:
    """Rename or enable/disable a linked subscription."""
    tenant_id = get_tenant_id(user)
    repo = _get_repo()
    rec = await repo.get(tenant_id, subscription_id.lower())
    if rec is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if body.display_name is not None:
        rec.display_name = body.display_name
    if body.state is not None:
        rec.state = body.state
    saved = await repo.upsert(rec)
    return SubscriptionResponse.from_record(saved)


@router.delete(
    "/{subscription_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
async def delete_subscription(
    subscription_id: str,
    user: TokenPayload = _auth,
) -> None:
    """Unlink a subscription from the caller's tenant."""
    tenant_id = get_tenant_id(user)
    repo = _get_repo()
    existed = await repo.delete(tenant_id, subscription_id.lower())
    if not existed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


# ---------------------------------------------------------------------------
# Cross-tenant consent flow (Phase 3.3)
# ---------------------------------------------------------------------------


_GUID_TID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class ConsentUrlResponse(BaseModel):
    """Response for ``GET /subscriptions/consent-url``."""

    consent_url: str
    customer_tenant_id: str


class ConsentRecordResponse(BaseModel):
    """Response for ``GET /subscriptions/consent-callback``."""

    customer_tenant_id: str
    consented_at: str
    status: str = "recorded"


def _build_consent_url(settings: Settings, tenant_id: str) -> str:
    """Return the Azure AD admin-consent URL for *tenant_id*.

    Microsoft documents the endpoint at
    ``https://login.microsoftonline.com/{tid}/adminconsent`` -- once the
    admin clicks Accept, Azure AD redirects back to our configured
    ``consent_redirect_uri`` with ``tenant`` and ``admin_consent``
    query parameters which the callback endpoint consumes.
    """
    if not settings.azure_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="azure_client_id not configured",
        )
    params = urlencode({
        "client_id": settings.azure_client_id,
        "redirect_uri": settings.consent_redirect_uri,
        # Random ``state`` is recommended; the frontend caches it before
        # opening the popup and verifies it on callback. Server side we
        # echo whatever the caller supplied so we do not mint a value
        # the frontend cannot anticipate.
    })
    return (
        f"https://login.microsoftonline.com/{tenant_id}/adminconsent?"
        f"{params}"
    )


@router.get("/consent-url", response_model=ConsentUrlResponse)
async def get_consent_url(
    tenant_id: str,
    user: TokenPayload = _auth,  # noqa: ARG001 -- auth required
) -> ConsentUrlResponse:
    """Return the admin-consent URL for *tenant_id*.

    The frontend opens this URL in a popup so a directory admin in the
    customer''s Entra tenant can grant consent for the CloudGuardIQ
    multi-tenant app.
    """
    customer_tid = tenant_id.strip().lower()
    if not _GUID_TID_RE.match(customer_tid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_tenant_id",
                "message": "tenant_id must be an Entra tenant GUID.",
            },
        )
    settings = _get_settings()
    return ConsentUrlResponse(
        consent_url=_build_consent_url(settings, customer_tid),
        customer_tenant_id=customer_tid,
    )


@router.get(
    "/consent-callback", response_model=ConsentRecordResponse,
)
async def consent_callback(
    tenant: str = "",
    admin_consent: str = "",
    error: str = "",
    error_description: str = "",
    user: TokenPayload = _auth,
) -> ConsentRecordResponse:
    """Record a successful admin-consent grant.

    Azure AD redirects the customer admin here with ``tenant`` (their
    tid) and ``admin_consent=True`` after they click Accept. We persist
    a :class:`TenantConsent` row keyed by that tid so subsequent
    ``POST /subscriptions`` calls for that tenant are unblocked.

    Errors from Azure AD (e.g. consent declined) are surfaced as
    ``400 consent_failed`` with the original ``error_description``.
    """
    if error:
        logger.info(
            "Consent callback error tenant=%s err=%s desc=%s",
            tenant, error, error_description,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "consent_failed",
                "azure_error": error,
                "azure_error_description": error_description,
            },
        )
    customer_tid = tenant.strip().lower()
    if not _GUID_TID_RE.match(customer_tid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_tenant_id",
                "message": "Azure AD did not return a valid tenant guid.",
            },
        )
    if admin_consent.lower() not in {"true", "1", "yes"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "consent_not_granted",
                "message": "admin_consent flag was not True.",
            },
        )

    consent_repo = _get_consent_repo()
    if consent_repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Tenant consent repository not configured",
        )

    consent = TenantConsent(
        customer_tenant_id=customer_tid,
        consented_by=user.oid or user.sub or "",
    )
    saved = await consent_repo.upsert(consent)
    logger.info(
        "Recorded admin consent customer_tid=%s consented_by=%s",
        customer_tid, saved.consented_by,
    )
    return ConsentRecordResponse(
        customer_tenant_id=saved.customer_tenant_id,
        consented_at=saved.consented_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# One-click onboarding (Phase 3.9 - simpler flow)
# ---------------------------------------------------------------------------


class DiscoveredSubscription(BaseModel):
    """A subscription returned by GET /subscriptions/discover."""

    subscription_id: str
    display_name: str = ""
    state: str = "Enabled"
    already_linked: bool = False


class DiscoverResponse(BaseModel):
    """Response payload for GET /subscriptions/discover."""

    customer_tenant_id: str
    subscriptions: list[DiscoveredSubscription]


class OnboardingTemplateResponse(BaseModel):
    """Response payload for GET /subscriptions/onboarding-template."""

    customer_tenant_id: str
    azure_principal_id: str
    template_uri: str
    deploy_url: str
    scope: str  # 'subscription' or 'managementGroup'


_GITHUB_BLOB_RE = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$"
)


def _normalize_template_uri(uri: str) -> str:
    """Rewrite GitHub HTML viewer URLs to raw.githubusercontent.com.

    The Azure Portal DeployToAzure blade fetches the URI directly and
    parses it as JSON. A ``https://github.com/<owner>/<repo>/blob/<ref>/<path>``
    URL returns an HTML preview page, which makes the blade fail with
    ``ErrorLoadingExtensionAndDefinition``. This helper rewrites such URLs
    to the matching ``https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>``
    form so a misconfigured ``CLOUDGUARDIQ_ONBOARDING_TEMPLATE_URI`` still
    works. Any other URL (raw GitHub, Azure Storage, custom CDN) is
    returned unchanged.
    """
    if not uri:
        return uri
    m = _GITHUB_BLOB_RE.match(uri.strip())
    if not m:
        return uri
    owner, repo, ref, path = m.groups()
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"


def _build_deploy_url(template_uri: str, scope: str) -> str:
    """Return an Azure Portal Deploy-to-Azure URL for the given scope.

    The portal accepts a ``#create/Microsoft.Template/uri/<encoded>``
    fragment which opens the Custom Deployment blade pre-filled with
    the template at *template_uri*. ``scope`` chooses the host blade:

    * ``subscription`` -> deploy at the currently-selected subscription
    * ``managementGroup`` -> deploy at a management group (recommended for
      the tenant root MG so all current and future subs are covered)
    """
    from urllib.parse import quote
    encoded = quote(template_uri, safe="")
    if scope == "managementGroup":
        return (
            f"https://portal.azure.com/#blade/Microsoft_Azure_Resources/"
            f"DeployToAzureMgBlade/uri/{encoded}"
        )
    return f"https://portal.azure.com/#create/Microsoft.Template/uri/{encoded}"


async def _list_customer_subscriptions(credential: Any) -> list[DiscoveredSubscription]:
    """Enumerate Azure subscriptions visible to *credential*.

    Runs the synchronous Azure SDK call in a thread pool so the FastAPI
    event loop is not blocked. Returns an empty list when the SDK is
    not installed (dev environments without azure-mgmt-resource).
    """
    import asyncio

    def _list_sync() -> list[DiscoveredSubscription]:
        from azure.mgmt.subscription import SubscriptionClient
        client = SubscriptionClient(credential)
        out: list[DiscoveredSubscription] = []
        for sub in client.subscriptions.list():
            sub_id = (getattr(sub, "subscription_id", "") or "").lower()
            if not sub_id:
                continue
            out.append(DiscoveredSubscription(
                subscription_id=sub_id,
                display_name=getattr(sub, "display_name", "") or sub_id,
                state=str(getattr(sub, "state", "Enabled") or "Enabled"),
            ))
        return out

    return await asyncio.get_running_loop().run_in_executor(None, _list_sync)


@router.get("/discover", response_model=DiscoverResponse)
async def discover_subscriptions(
    tenant_id: str = "",
    user: TokenPayload = _auth,
) -> DiscoverResponse:
    """List Azure subscriptions visible to CloudGuardIQ in *tenant_id*.

    Replaces the manual GUID-typing step in the simpler onboarding flow.
    Requires:

    1. Recorded admin consent for the customer tenant (see
       ``GET /subscriptions/consent-url``).
    2. Reader role granted to CloudGuardIQ at subscription or
       management-group scope (see
       ``GET /subscriptions/onboarding-template`` for the one-click
       Deploy-to-Azure button).

    Returns ``400 reader_role_required`` when consent exists but no
    Reader role assignment is found yet -- the response includes the
    deploy URL so the frontend can surface it inline.
    """
    caller_tid = get_tenant_id(user)
    customer_tid = (tenant_id or caller_tid).strip().lower()
    settings = _get_settings()

    if customer_tid != caller_tid.lower() and not settings.auth_disabled:
        consent_repo = _get_consent_repo()
        if consent_repo is None or not await consent_repo.has_active_consent(
            customer_tid,
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "consent_required",
                    "customer_tenant_id": customer_tid,
                    "message": (
                        "Open the consent URL from "
                        "GET /subscriptions/consent-url first."
                    ),
                },
            )

    if _credential_factory is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cross-tenant credential factory not configured.",
        )
    try:
        credential = _credential_factory.for_tenant(customer_tid)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Credential build failed tenant=%s: %s", customer_tid, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to build customer-tenant credential.",
        ) from exc

    try:
        discovered = await _list_customer_subscriptions(credential)
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        # 401/403/AuthorizationFailed all collapse to the same UX:
        # consent worked but Reader is missing -> show deploy button.
        rbac_tokens = (
            "AuthorizationFailed", "403", "401", "Forbidden", "Unauthorized",
        )
        if any(tok in msg for tok in rbac_tokens):
            logger.info(
                "Discover blocked by RBAC tenant=%s: %s", customer_tid, msg,
            )
            info = OnboardingInfo.build()
            template_uri = _normalize_template_uri(settings.onboarding_template_uri)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "reader_role_required",
                    "customer_tenant_id": customer_tid,
                    "azure_principal_id": info.azure_principal_id,
                    "template_uri": template_uri,
                    "deploy_url": (
                        _build_deploy_url(template_uri, "managementGroup")
                        if template_uri else ""
                    ),
                    "message": (
                        "CloudGuardIQ has consent but no Reader role in this "
                        "tenant. Click the Deploy-to-Azure button to grant "
                        "Reader at the tenant root management group, then "
                        "retry discovery."
                    ),
                },
            ) from exc
        logger.exception("Discover failed tenant=%s", customer_tid)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Azure subscription enumeration failed: {msg}",
        ) from exc

    # Annotate already-linked subscriptions so the UI can disable them.
    repo = _get_repo()
    existing = {r.subscription_id for r in await repo.list(caller_tid)}
    for sub in discovered:
        if sub.subscription_id in existing:
            sub.already_linked = True

    logger.info(
        "Discovered subs tenant=%s count=%d", customer_tid, len(discovered),
    )
    return DiscoverResponse(
        customer_tenant_id=customer_tid,
        subscriptions=discovered,
    )


@router.get("/onboarding-template", response_model=OnboardingTemplateResponse)
async def get_onboarding_template(
    tenant_id: str = "",
    scope: str = "managementGroup",
    user: TokenPayload = _auth,
) -> OnboardingTemplateResponse:
    """Return the Deploy-to-Azure URL that grants Reader to CloudGuardIQ.

    *scope* is ``subscription`` or ``managementGroup``. Pick
    ``managementGroup`` to cover all current and future subs in one
    deployment; pick ``subscription`` to scope the grant tightly.
    """
    if scope not in ("subscription", "managementGroup"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="scope must be 'subscription' or 'managementGroup'.",
        )
    caller_tid = get_tenant_id(user)
    customer_tid = (tenant_id or caller_tid).strip().lower()
    settings = _get_settings()
    template_uri = _normalize_template_uri(settings.onboarding_template_uri)
    if not template_uri:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "onboarding_template_uri is not configured; "
                "set CLOUDGUARDIQ_ONBOARDING_TEMPLATE_URI on the API."
            ),
        )
    info = OnboardingInfo.build()
    return OnboardingTemplateResponse(
        customer_tenant_id=customer_tid,
        azure_principal_id=info.azure_principal_id,
        template_uri=template_uri,
        deploy_url=_build_deploy_url(template_uri, scope),
        scope=scope,
    )
