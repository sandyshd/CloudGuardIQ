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

from cloudguardiq.api.auth import TokenPayload, get_tenant_id, verify_token
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
    """Body for ``POST /subscriptions``."""

    subscription_id: str = Field(..., min_length=36, max_length=36)
    display_name: str = ""

    @field_validator("subscription_id")
    @classmethod
    def _validate_guid(cls, v: str) -> str:
        if not _GUID_RE.match(v):
            raise ValueError("subscription_id must be an Azure GUID")
        return v.lower()


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

    record = await billing.get(tenant_id)
    tier = record.tier if record else SubscriptionTier.FREE
    cap = _cap_for_tier(settings, tier)

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
