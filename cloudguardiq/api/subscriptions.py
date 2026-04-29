"""CloudGuardIQ -- Subscription management FastAPI routes (Phase 2).

Tenants manage their linked Azure subscriptions through this router. Tier
caps are enforced here using the JWT ``tid`` claim.
"""

from __future__ import annotations

import logging
import re
from typing import Any

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
) -> None:
    """Wire dependencies from the application startup hook."""
    global _repository, _billing_repo, _settings  # noqa: PLW0603
    _repository = repository
    _billing_repo = billing_repository
    _settings = settings


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


async def _run_access_probe(subscription_id: str) -> AccessProbeResult | None:
    """Run the access probe (test override or default Resource Graph).

    Returns ``None`` when the probe cannot be executed (no Azure credential
    available, e.g. local dev without ``az login``); the caller treats
    ``None`` as a soft-pass so contributors are not blocked offline.
    """
    if _probe_override is not None:
        return await _probe_override(subscription_id)
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
    repo = _get_repo()
    billing = _get_billing()
    settings = _get_settings()

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
        probe_result = await _run_access_probe(body.subscription_id)
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
