"""CloudGuardIQ -- Subscription management FastAPI routes (Phase 2).

Tenants manage their linked Azure subscriptions through this router. Tier
caps are enforced here using the JWT ``tid`` claim.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
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
from cloudguardiq.auth.graph_principal_resolver import (
    PrincipalLookupError,
    PrincipalNotFoundError,
    resolve_customer_principal_id,
)
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
from cloudguardiq.tenants.onboarding_session_repository import (
    OnboardingSession,
    OnboardingSessionRepository,
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
    provider: str = "AZURE"
    aws_account_id: str = ""
    gcp_project_id: str = ""

    @classmethod
    def from_record(cls, rec: SubscriptionRecord) -> SubscriptionResponse:
        """Build a response payload from a stored record."""
        return cls(
            subscription_id=rec.subscription_id,
            display_name=rec.display_name or rec.subscription_id,
            state=rec.state,
            provider=rec.provider.value,
            aws_account_id=rec.aws_account_id,
            gcp_project_id=rec.gcp_project_id,
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
_onboarding_repo: OnboardingSessionRepository | None = None
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
    onboarding_session_repository: OnboardingSessionRepository | None = None,
    credential_factory: object | None = None,
) -> None:
    """Wire dependencies from the application startup hook.

    *consent_repository* and *credential_factory* are Phase 3 additions
    used to enforce admin consent and to authenticate against the
    customer's Entra tenant when probing cross-tenant subscriptions.
    Both are optional so single-tenant deployments keep working.
    """
    global _repository, _billing_repo, _settings  # noqa: PLW0603
    global _consent_repo, _onboarding_repo, _credential_factory  # noqa: PLW0603
    _repository = repository
    _billing_repo = billing_repository
    _settings = settings
    _consent_repo = consent_repository
    _onboarding_repo = onboarding_session_repository
    _credential_factory = credential_factory


def _get_consent_repo() -> TenantConsentRepository | None:
    """Return the configured consent repository or ``None``."""
    return _consent_repo

def _get_onboarding_repo() -> OnboardingSessionRepository | None:
    """Return the configured onboarding session repository or ``None``."""
    return _onboarding_repo


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
    """Return subscriptions visible to the caller tenant."""
    tenant_id = get_tenant_id(user)
    repo = _get_repo()
    records = await repo.list(tenant_id)

    # Backward-compatibility bridge: older cross-tenant enrollments stored
    # records under the operator tenant_id. On first customer login we
    # materialize customer-owned rows so the customer can see/manage them.
    if not records:
        legacy = await repo.list_by_customer_tenant(tenant_id)
        for rec in legacy:
            exists = await repo.get(tenant_id, rec.subscription_id)
            if exists is not None:
                continue
            claimed = SubscriptionRecord(
                tenant_id=tenant_id,
                subscription_id=rec.subscription_id,
                customer_tenant_id=rec.customer_tenant_id or tenant_id,
                display_name=rec.display_name,
                state=rec.state,
                added_at=rec.added_at,
                last_scan_at=rec.last_scan_at,
                removed_at=rec.removed_at,
            )
            await repo.upsert(claimed)
            records.append(claimed)

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
    raw_customer_tid = (body.customer_tenant_id or tenant_id).strip()
    customer_tid = (
        raw_customer_tid.lower()
        if _GUID_TID_RE.match(raw_customer_tid)
        else raw_customer_tid
    )
    repo = _get_repo()
    billing = _get_billing()
    settings = _get_settings()
    owning_tenant_id = customer_tid

    # Cross-tenant guard (Phase 3.4): when the customer tenant differs
    # from the caller's tenant we must have a recorded admin consent
    # before we can issue an Azure access probe against it. Without
    # this guard a malicious caller could try to brute-force tenant
    # ids by triggering access probes through us.
    if customer_tid.lower() != tenant_id.lower() and not settings.auth_disabled:
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

    record = await billing.get(owning_tenant_id)
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
    existing = await repo.get(owning_tenant_id, body.subscription_id)
    if existing is not None and existing.state == "Removed":
        existing.state = "Enabled"
        existing.removed_at = None
        if body.display_name:
            existing.display_name = body.display_name
        restored = await repo.upsert(existing)
        logger.info(
            "Restored soft-deleted subscription tenant=%s owner=%s sub=%s",
            tenant_id, owning_tenant_id, body.subscription_id,
        )
        return SubscriptionResponse.from_record(restored)

    current = await repo.count(owning_tenant_id)
    if cap >= 0 and current >= cap:
        logger.info(
            "Tier cap reached: owner=%s requested_by=%s tier=%s current=%d cap=%d",
            owning_tenant_id, tenant_id, tier.value, current, cap,
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
        tenant_id=owning_tenant_id,
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

class OnboardingSessionCreateRequest(BaseModel):
    """Body for ``POST /subscriptions/onboarding-sessions``."""

    customer_tenant_id: str


class OnboardingSessionConnectRequest(BaseModel):
    """Body for ``POST /subscriptions/onboarding-sessions/{id}/connect``."""

    subscription_ids: list[str] = Field(default_factory=list)


class OnboardingSessionResponse(BaseModel):
    """Status payload for a simplified onboarding session."""

    session_id: str
    customer_tenant_id: str
    status: str
    consent_url: str
    discovered_subscription_ids: list[str] = Field(default_factory=list)
    connected_subscription_ids: list[str] = Field(default_factory=list)


def _to_onboarding_session_response(
    session: OnboardingSession,
    settings: Settings,
) -> OnboardingSessionResponse:
    """Map persistent session state to API response."""
    return OnboardingSessionResponse(
        session_id=session.session_id,
        customer_tenant_id=session.customer_tenant_id,
        status=session.status,
        consent_url=_build_consent_url(
            settings,
            session.customer_tenant_id,
            state=session.session_id,
        ),
        discovered_subscription_ids=session.discovered_subscription_ids,
        connected_subscription_ids=session.connected_subscription_ids,
    )


async def _get_session_or_404(
    user: TokenPayload,
    session_id: str,
) -> OnboardingSession:
    """Return one onboarding session scoped to the caller tenant."""
    repo = _get_onboarding_repo()
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Onboarding session repository not configured",
        )
    tenant_id = get_tenant_id(user)
    session = await repo.get(tenant_id, session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Onboarding session not found",
        )
    return session



def _build_consent_url(settings: Settings, tenant_id: str, state: str = "") -> str:
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
    payload = {
        "client_id": settings.azure_client_id,
        "redirect_uri": settings.consent_redirect_uri,
    }
    if state:
        payload["state"] = state
    params = urlencode(payload)
    return (
        f"https://login.microsoftonline.com/{tenant_id}/adminconsent?"
        f"{params}"
    )


@router.get("/consent-url", response_model=ConsentUrlResponse)
async def get_consent_url(
    tenant_id: str,
    state: str = "",
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
        consent_url=_build_consent_url(settings, customer_tid, state=state),
        customer_tenant_id=customer_tid,
    )


@router.post(
    "/onboarding-sessions",
    response_model=OnboardingSessionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_onboarding_session(
    body: OnboardingSessionCreateRequest,
    user: TokenPayload = _auth,
) -> OnboardingSessionResponse:
    """Create a streamlined onboarding session for one customer tenant."""
    customer_tid = body.customer_tenant_id.strip().lower()
    if not _GUID_TID_RE.match(customer_tid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_tenant_id",
                "message": "customer_tenant_id must be an Entra tenant GUID.",
            },
        )

    tenant_id = get_tenant_id(user)
    settings = _get_settings()
    consent_repo = _get_consent_repo()
    has_consent = (
        settings.auth_disabled
        or customer_tid == tenant_id.lower()
        or (
            consent_repo is not None
            and await consent_repo.has_active_consent(customer_tid)
        )
    )

    repo = _get_onboarding_repo()
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Onboarding session repository not configured",
        )

    session = OnboardingSession(
        session_id=uuid.uuid4().hex,
        operator_tenant_id=tenant_id,
        customer_tenant_id=customer_tid,
        status="pending_reader" if has_consent else "pending_consent",
        consented_at=datetime.now(timezone.utc) if has_consent else None,
    )
    saved = await repo.upsert(session)
    return _to_onboarding_session_response(saved, settings)


@router.get(
    "/onboarding-sessions/{session_id}",
    response_model=OnboardingSessionResponse,
)
async def get_onboarding_session(
    session_id: str,
    user: TokenPayload = _auth,
) -> OnboardingSessionResponse:
    """Return onboarding session status for the current operator tenant."""
    settings = _get_settings()
    session = await _get_session_or_404(user, session_id)

    if session.status == "pending_consent":
        consent_repo = _get_consent_repo()
        if consent_repo is not None and await consent_repo.has_active_consent(
            session.customer_tenant_id,
        ):
            session.status = "pending_reader"
            session.consented_at = datetime.now(timezone.utc)
            repo = _get_onboarding_repo()
            if repo is not None:
                await repo.upsert(session)

    return _to_onboarding_session_response(session, settings)


@router.post(
    "/onboarding-sessions/{session_id}/reader-granted",
    response_model=OnboardingSessionResponse,
)
async def mark_onboarding_reader_granted(
    session_id: str,
    user: TokenPayload = _auth,
) -> OnboardingSessionResponse:
    """Mark that customer RBAC grant was completed by admin."""
    settings = _get_settings()
    session = await _get_session_or_404(user, session_id)
    session.status = "pending_discovery"
    session.reader_granted_at = datetime.now(timezone.utc)
    repo = _get_onboarding_repo()
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Onboarding session repository not configured",
        )
    await repo.upsert(session)
    return _to_onboarding_session_response(session, settings)


@router.post(
    "/onboarding-sessions/{session_id}/discover",
    response_model=OnboardingSessionResponse,
)
async def discover_onboarding_session_subscriptions(
    session_id: str,
    user: TokenPayload = _auth,
) -> OnboardingSessionResponse:
    """Discover customer subscriptions and persist them on a session."""
    settings = _get_settings()
    session = await _get_session_or_404(user, session_id)
    res = await discover_subscriptions(
        tenant_id=session.customer_tenant_id,
        user=user,
    )
    session.status = "subscriptions_discovered"
    session.discovered_subscription_ids = [
        s.subscription_id for s in res.subscriptions if not s.already_linked
    ]
    repo = _get_onboarding_repo()
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Onboarding session repository not configured",
        )
    await repo.upsert(session)
    return _to_onboarding_session_response(session, settings)


@router.post(
    "/onboarding-sessions/{session_id}/connect",
    response_model=OnboardingSessionResponse,
)
async def connect_onboarding_session_subscriptions(
    session_id: str,
    body: OnboardingSessionConnectRequest,
    user: TokenPayload = _auth,
) -> OnboardingSessionResponse:
    """Link discovered subscriptions and mark onboarding complete."""
    settings = _get_settings()
    session = await _get_session_or_404(user, session_id)
    candidate_ids = body.subscription_ids or session.discovered_subscription_ids
    subscription_ids = [
        sid.strip().lower() for sid in candidate_ids if sid.strip()
    ]
    if not subscription_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "no_subscriptions_selected",
                "message": "Provide subscription_ids or run discover first.",
            },
        )

    connected: list[str] = []
    for sid in subscription_ids:
        await add_subscription(
            AddSubscriptionRequest(
                subscription_id=sid,
                customer_tenant_id=session.customer_tenant_id,
            ),
            user=user,
        )
        connected.append(sid)

    merged = session.connected_subscription_ids + connected
    session.connected_subscription_ids = list(dict.fromkeys(merged))
    session.status = "completed"

    repo = _get_onboarding_repo()
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Onboarding session repository not configured",
        )
    await repo.upsert(session)
    return _to_onboarding_session_response(session, settings)

@router.get(
    "/consent-callback", response_model=ConsentRecordResponse,
)
async def consent_callback(
    tenant: str = "",
    admin_consent: str = "",
    error: str = "",
    error_description: str = "",
    state: str = "",
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

    onboarding_repo = _get_onboarding_repo()
    caller_tid = get_tenant_id(user)
    if onboarding_repo is not None and state:
        session = await onboarding_repo.get(caller_tid, state.strip())
        if session is not None:
            session.status = "pending_reader"
            session.consented_at = datetime.now(timezone.utc)
            await onboarding_repo.upsert(session)

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
    parameters_uri: str = ""
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
    # Strip surrounding whitespace and any wrapping quote/backtick characters.
    # A common misconfiguration is setting the env var or CI secret to
    # ``'https://.../template.json'`` (with literal quotes), which gets
    # URL-encoded to a trailing ``%27`` in the Deploy-to-Azure link and makes
    # the Portal fail with "error downloading the template".
    cleaned = uri.strip().strip("'\"`").strip()
    m = _GITHUB_BLOB_RE.match(cleaned)
    if not m:
        return cleaned
    owner, repo, ref, path = m.groups()
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"


# Path (relative to the API router prefix ``/subscriptions``) at which the
# bundled CloudGuardIQ Reader ARM template is served anonymously. The Azure
# Portal Deploy-to-Azure blade fetches this URL when the customer clicks the
# one-click button, so it must remain stable and unauthenticated.
_BUNDLED_TEMPLATE_PATH = "/subscriptions/onboarding-template.json"


def _resolve_template_uri(settings: Settings) -> str:
    """Return the effective ARM template URL for the Deploy-to-Azure flow.

    Resolution order:

    1. ``CLOUDGUARDIQ_ONBOARDING_TEMPLATE_URI`` if explicitly set --
       normalized (strips wrapping quotes, rewrites GitHub blob URLs).
    2. The bundled template served by this API at
       ``{public_api_base_url}{_BUNDLED_TEMPLATE_PATH}`` -- used when the
       env var is unset so a private GitHub repo does not break onboarding.
    3. Empty string -- callers translate this into HTTP 503 (one-click
       disabled; the manual ``az role assignment`` flow still works).
    """
    explicit = _normalize_template_uri(settings.onboarding_template_uri)
    if explicit:
        return explicit
    base = (settings.public_api_base_url or "").strip().strip("'\"`").strip()
    if not base:
        return ""
    return f"{base.rstrip('/')}{_BUNDLED_TEMPLATE_PATH}"


def _build_parameters_uri(base_url: str, principal_id: str) -> str:
    """Return a public URL that serves ARM deployment parameters.

    The URL is fed into the Azure Portal Deploy-to-Azure blade via
    ``/uriParameters/<encoded>`` so the customer-tenant CloudGuardIQ
    service principal id is pre-populated and the operator only has
    to click Review + create. Returns an empty string when either
    ``base_url`` is unset (prefill disabled) or ``principal_id`` is
    not a well-formed GUID (defensive: never emit malformed URLs).
    """
    if not base_url or not principal_id:
        return ""
    if not _GUID_RE.match(principal_id):
        return ""
    base = base_url.rstrip("/")
    return f"{base}/subscriptions/onboarding-parameters/{principal_id}"


def _build_deploy_url(
    template_uri: str, scope: str, parameters_uri: str = ""
) -> str:
    """Return an Azure Portal Deploy-to-Azure URL.

    The universal, documented Deploy-to-Azure URL is
    ``https://portal.azure.com/#create/Microsoft.Template/uri/<encoded>``.
    The portal reads the template\'s ``$schema`` to route to the correct
    deployment blade (resource group, subscription, management group, or
    tenant). ``scope`` is accepted for API/wizard compatibility but does
    not change the URL -- the portal infers the scope from the template
    itself, which avoids 404s on non-public blade names like
    ``DeployToAzureMgBlade``.

    * Subscription-scoped templates (``$schema`` =
      ``deploymentTemplate.json``) prompt for a subscription/RG.
    * Management-group-scoped templates (``$schema`` =
      ``managementGroupDeploymentTemplate.json``) prompt for an MG.
    """
    from urllib.parse import quote
    del scope  # informational only; portal routes via $schema
    encoded = quote(template_uri, safe="")
    url = f"https://portal.azure.com/#create/Microsoft.Template/uri/{encoded}"
    if parameters_uri:
        url += f"/uriParameters/{quote(parameters_uri, safe='')}"
    return url


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
            template_uri = _resolve_template_uri(settings)
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


async def _resolve_principal_for_tenant(
    settings: Settings, *, caller_tid: str, customer_tid: str,
) -> str:
    """Return the CloudGuardIQ SP object id to grant Reader to.

    Strategy:

    1. If a cross-tenant credential factory is wired and ``azure_client_id``
       is configured, ask Microsoft Graph for the SP object id that the
       customer tenant materialised on admin consent. This is the
       *correct* value for any tenant (home or customer).
    2. If the Graph lookup says the SP does not exist
       (:class:`PrincipalNotFoundError`), the customer has not granted
       admin consent yet -- raise 409 with the consent URL so the wizard
       can prompt the admin.
    3. On any other Graph failure for a non-home tenant, surface 502.
    4. For the home tenant (or when no factory is configured), fall back
       to the env-var-derived value from :class:`OnboardingInfo` -- this
       keeps single-tenant / dev deployments working.
    """
    home_tid = (settings.azure_tenant_id or "").strip().lower()
    client_id = settings.azure_client_id or ""
    is_home = (
        customer_tid == home_tid
        or (not home_tid and customer_tid == caller_tid.lower())
    )

    if _credential_factory is not None and client_id:
        try:
            return await resolve_customer_principal_id(
                _credential_factory,  # type: ignore[arg-type]
                client_id=client_id,
                tenant_id=customer_tid,
            )
        except PrincipalNotFoundError as exc:
            logger.info(
                "Onboarding blocked for tenant=%s: no consented SP (%s)",
                customer_tid, exc,
            )
            consent_url = _build_consent_url(settings, customer_tid)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "consent_required",
                    "message": (
                        "CloudGuardIQ is not yet admin-consented in this "
                        "tenant. An Entra ID Global Administrator must "
                        "accept the consent URL before the deployment can "
                        "grant a role to CloudGuardIQ."
                    ),
                    "consent_url": consent_url,
                    "customer_tenant_id": customer_tid,
                },
            ) from exc
        except PrincipalLookupError as exc:
            logger.warning(
                "Graph principal lookup failed for tenant=%s: %s",
                customer_tid, exc,
            )
            if not is_home:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail={
                        "error": "principal_lookup_failed",
                        "message": (
                            "Could not resolve CloudGuardIQ's principal id "
                            "in the target tenant. Retry; if the problem "
                            "persists, contact support."
                        ),
                    },
                ) from exc
            # Home tenant: fall through to env-var fallback.

    # Home-tenant / dev fallback: prefer the explicit value on the wired
    # ``Settings`` instance (this is what tests inject) and only fall back
    # to ``OnboardingInfo.build()`` -- which re-reads the global settings
    # and invokes the runtime identity resolver -- when nothing was set.
    if settings.azure_principal_id:
        return settings.azure_principal_id
    info = OnboardingInfo.build()
    return info.azure_principal_id


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
    template_uri = _resolve_template_uri(settings)
    if not template_uri:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "onboarding template URL is not configured; set "
                "CLOUDGUARDIQ_ONBOARDING_TEMPLATE_URI or "
                "CLOUDGUARDIQ_PUBLIC_API_BASE_URL on the API."
            ),
        )
    principal_id = await _resolve_principal_for_tenant(
        settings, caller_tid=caller_tid, customer_tid=customer_tid,
    )
    parameters_uri = _build_parameters_uri(
        settings.public_api_base_url, principal_id,
    )
    return OnboardingTemplateResponse(
        customer_tenant_id=customer_tid,
        azure_principal_id=principal_id,
        template_uri=template_uri,
        deploy_url=_build_deploy_url(
            template_uri, scope, parameters_uri=parameters_uri,
        ),
        parameters_uri=parameters_uri,
        scope=scope,
    )


@router.get(
    "/onboarding-parameters/{principal_id}",
    include_in_schema=False,
    responses={200: {"content": {"application/json": {}}}},
)
async def get_onboarding_parameters(principal_id: str) -> Response:
    """Return the ARM deployment parameters file for one principal.

    The Azure Portal Deploy-to-Azure blade fetches this URL (anonymously)
    to pre-populate ``cloudGuardIQPrincipalId`` in the customer-tenant
    role-assignment template. The endpoint is intentionally unauthenticated
    so the portal can fetch it; the only data echoed back is the GUID the
    caller already provides in the path, so no information is leaked.
    """
    if not _GUID_RE.match(principal_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="principal_id must be a valid GUID.",
        )
    body = {
        "$schema": (
            "https://schema.management.azure.com/schemas/"
            "2019-04-01/deploymentParameters.json#"
        ),
        "contentVersion": "1.0.0.0",
        "parameters": {
            "cloudGuardIQPrincipalId": {"value": principal_id},
        },
    }
    import json
    return Response(
        content=json.dumps(body),
        media_type="application/json",
        headers={
            "Cache-Control": "public, max-age=300",
            "Access-Control-Allow-Origin": "*",
        },
    )


# Cached copy of the bundled ARM template body. Read once at first request
# and reused thereafter -- the file ships inside the wheel, so the contents
# cannot change between calls within a single process.
_BUNDLED_TEMPLATE_BODY: bytes | None = None


def _load_bundled_template() -> bytes:
    """Load the CloudGuardIQ Reader ARM template bundled in the wheel.

    The file lives at ``cloudguardiq/api/templates/cloudguardiq-reader.json``
    and is shipped via ``[tool.setuptools.package-data]`` in
    ``pyproject.toml``. Using ``importlib.resources`` is robust to whether
    the package is installed from a wheel, an editable install, or a
    zipped artifact.
    """
    global _BUNDLED_TEMPLATE_BODY
    if _BUNDLED_TEMPLATE_BODY is not None:
        return _BUNDLED_TEMPLATE_BODY
    from importlib.resources import files
    pkg = files("cloudguardiq.api.templates")
    _BUNDLED_TEMPLATE_BODY = (pkg / "cloudguardiq-reader.json").read_bytes()
    return _BUNDLED_TEMPLATE_BODY


@router.get(
    "/onboarding-template.json",
    include_in_schema=False,
    responses={200: {"content": {"application/json": {}}}},
)
async def get_onboarding_template_json() -> Response:
    """Serve the CloudGuardIQ Reader ARM template anonymously.

    The Azure Portal Deploy-to-Azure blade fetches this URL when the
    customer clicks the one-click onboarding button. Hosting the template
    from the API (instead of ``raw.githubusercontent.com``) lets the
    GitHub repository stay private and removes the GitHub branch/path
    coupling -- the template version always matches the running API.

    The route is intentionally unauthenticated and CORS-open for the
    Azure Portal origin. The body is a static, non-sensitive ARM template
    (no secrets, no tenant data), so anonymous access is safe.
    """
    return Response(
        content=_load_bundled_template(),
        media_type="application/json",
        headers={
            "Cache-Control": "public, max-age=3600",
            "Access-Control-Allow-Origin": "*",
        },
    )

