"""CloudGuardIQ -- Stripe billing FastAPI routes."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel

from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.billing.plans import PlanLimits, all_plans, default_tier
from cloudguardiq.billing.repository import BillingCustomer, BillingRepository
from cloudguardiq.billing.stripe_service import StripeService, StripeServiceError
from cloudguardiq.core.config import get_settings
from cloudguardiq.core.enums import SubscriptionTier

logger = logging.getLogger(__name__)


class CheckoutRequest(BaseModel):
    """Body for ``POST /billing/checkout``."""

    tier: SubscriptionTier


class CheckoutResponse(BaseModel):
    """Response for ``POST /billing/checkout``."""

    url: str


class ChangeTierRequest(BaseModel):
    """Body for ``POST /billing/downgrade``."""

    tier: SubscriptionTier


class SelectTierRequest(BaseModel):
    """Body for ``POST /billing/select`` (direct plan change)."""

    tier: SubscriptionTier


class BillingStatusResponse(BaseModel):
    """Response for ``GET /billing/status``."""

    tier: SubscriptionTier
    stripe_customer_id: str = ""
    stripe_subscription_id: str = ""


class PlanCatalogResponse(BaseModel):
    """Response for ``GET /billing/plans``."""

    plans: list[PlanLimits]
    defender_auto_enrichment: bool = True
    defender_note: str = (
        "Defender for Cloud signals are auto-detected and used to enrich "
        "findings on every plan at no extra charge. CloudGuardIQ never "
        "requires Defender to be enabled."
    )


# ---------------------------------------------------------------------------
# Module-level accessors wired up from the main app at startup.
# ---------------------------------------------------------------------------

_repository: BillingRepository | None = None
_stripe_service: StripeService | None = None
_invalidate_cache: Any = None  # optional callable(tenant_id) from middleware


def configure(
    *,
    repository: BillingRepository,
    stripe_service: StripeService,
    invalidate_cache: Any = None,
) -> None:
    """Wire dependencies from the application startup hook."""
    global _repository, _stripe_service, _invalidate_cache  # noqa: PLW0603
    _repository = repository
    _stripe_service = stripe_service
    _invalidate_cache = invalidate_cache


def _get_repository() -> BillingRepository:
    """Return the configured repository or raise."""
    if _repository is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing repository not configured",
        )
    return _repository


def _get_stripe() -> StripeService:
    """Return the configured Stripe service or raise."""
    if _stripe_service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stripe service not configured",
        )
    return _stripe_service


def _tenant_id(user: TokenPayload) -> str:
    """Derive a tenant id from the authenticated principal.

    Prefers the JWT ``tid`` claim (Azure AD tenant). Falls back to ``sub``
    for development / dev-mode tokens that lack ``tid``.
    """
    return user.tid or user.sub or "anonymous"


def _stripe_enabled() -> bool:
    """Return True when Stripe checkout is the source of truth."""
    return bool(get_settings().billing_stripe_enabled)


def _default_tier() -> SubscriptionTier:
    """Default tier for tenants without a billing record."""
    return default_tier(get_settings())


router = APIRouter(prefix="/billing", tags=["billing"])

_auth = Depends(verify_token)


@router.get("/plans", response_model=PlanCatalogResponse)
async def get_plans() -> PlanCatalogResponse:
    """Return the public subscription plan catalog.

    This route is intentionally unauthenticated: the catalog is public
    marketing/pricing data and the Settings page renders it before the
    user has chosen a plan.
    """
    return PlanCatalogResponse(plans=all_plans())


@router.get("/status", response_model=BillingStatusResponse)
async def get_status(
    user: TokenPayload = _auth,
) -> BillingStatusResponse:
    """Return the current subscription tier for the caller."""
    repo = _get_repository()
    record = await repo.get(_tenant_id(user))
    if record is None:
        return BillingStatusResponse(tier=_default_tier())
    return BillingStatusResponse(
        tier=record.tier,
        stripe_customer_id=record.stripe_customer_id,
        stripe_subscription_id=record.stripe_subscription_id,
    )


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(
    body: CheckoutRequest,
    user: TokenPayload = _auth,
) -> CheckoutResponse:
    """Create a Stripe checkout session and return its redirect URL."""
    if body.tier == SubscriptionTier.FREE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot create a checkout session for the free tier",
        )
    repo = _get_repository()
    stripe = _get_stripe()
    tenant_id = _tenant_id(user)

    record = await repo.get(tenant_id) or BillingCustomer(tenant_id=tenant_id)
    try:
        customer_id = await stripe.ensure_customer(
            tenant_id=tenant_id,
            existing_customer_id=record.stripe_customer_id or None,
        )
        price_id = stripe.price_id_for_tier(body.tier)
        url = await stripe.create_checkout_session(
            customer_id=customer_id,
            price_id=price_id,
        )
    except StripeServiceError as exc:
        logger.warning("Checkout failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc

    record.stripe_customer_id = customer_id
    await repo.upsert(record)
    return CheckoutResponse(url=url)


@router.post("/select", response_model=BillingStatusResponse)
async def select_tier(
    body: SelectTierRequest,
    user: TokenPayload = _auth,
) -> BillingStatusResponse:
    """Set the caller tenant to any tier directly (Stripe-free mode).

    Available only while Stripe is disabled. Lets users freely upgrade or
    downgrade between plans without a payment round-trip. When Stripe is
    enabled, upgrades MUST go through ``POST /billing/checkout`` instead.
    """
    if _stripe_enabled():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Direct plan selection is disabled. Use /billing/checkout "
                "to upgrade or /billing/downgrade to downgrade."
            ),
        )
    repo = _get_repository()
    tenant_id = _tenant_id(user)
    record = await repo.get(tenant_id) or BillingCustomer(tenant_id=tenant_id)

    record.tier = body.tier
    if body.tier == SubscriptionTier.FREE:
        record.stripe_subscription_id = ""
    await repo.upsert(record)

    if callable(_invalidate_cache):
        try:
            _invalidate_cache(record.tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Cache invalidate failed: %s", exc)

    return BillingStatusResponse(
        tier=record.tier,
        stripe_customer_id=record.stripe_customer_id,
        stripe_subscription_id=record.stripe_subscription_id,
    )


@router.post("/downgrade", response_model=BillingStatusResponse)
async def downgrade_tier(
    body: ChangeTierRequest,
    user: TokenPayload = _auth,
) -> BillingStatusResponse:
    """Move the caller tenant to a lower tier.

    Direct tier write (no Stripe round-trip). Upgrades MUST go through
    ``POST /billing/checkout`` so Stripe stays the source of truth for
    paid subscriptions.
    """
    repo = _get_repository()
    tenant_id = _tenant_id(user)
    record = await repo.get(tenant_id) or BillingCustomer(tenant_id=tenant_id)

    rank = {
        SubscriptionTier.FREE: 0,
        SubscriptionTier.PRO: 1,
        SubscriptionTier.ENTERPRISE: 2,
    }
    if rank[body.tier] >= rank[record.tier]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Target tier must be lower than the current tier. "
                "Use /billing/checkout to upgrade."
            ),
        )

    record.tier = body.tier
    if body.tier == SubscriptionTier.FREE:
        record.stripe_subscription_id = ""
    await repo.upsert(record)

    if callable(_invalidate_cache):
        try:
            _invalidate_cache(record.tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Cache invalidate failed: %s", exc)

    return BillingStatusResponse(
        tier=record.tier,
        stripe_customer_id=record.stripe_customer_id,
        stripe_subscription_id=record.stripe_subscription_id,
    )


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    stripe_signature: str | None = Header(default=None, alias="Stripe-Signature"),
) -> dict[str, str]:
    """Handle Stripe subscription lifecycle webhooks."""
    if stripe_signature is None:
        raise HTTPException(status_code=400, detail="Missing signature")
    repo = _get_repository()
    stripe = _get_stripe()

    payload = await request.body()
    try:
        event = stripe.verify_webhook(
            payload=payload,
            signature=stripe_signature,
        )
    except StripeServiceError as exc:
        logger.warning("Webhook rejected: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    event_type = event.get("type", "")
    data = event.get("data", {}).get("object", {}) if isinstance(event, dict) else {}
    customer_id = str(data.get("customer", ""))
    if not customer_id:
        return {"status": "ignored"}

    record = await repo.get_by_customer_id(customer_id)
    if record is None:
        logger.info("Webhook for unknown customer %s", customer_id)
        return {"status": "unknown_customer"}

    if event_type == "customer.subscription.deleted":
        record.tier = SubscriptionTier.FREE
        record.stripe_subscription_id = ""
    elif event_type == "customer.subscription.updated":
        items = data.get("items", {}).get("data", [])
        price_id = ""
        if items:
            price_id = items[0].get("price", {}).get("id", "")
        record.tier = stripe.tier_for_price_id(price_id)
        record.stripe_subscription_id = str(data.get("id", ""))
    else:
        return {"status": "ignored"}

    await repo.upsert(record)
    if callable(_invalidate_cache):
        try:
            _invalidate_cache(record.tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Cache invalidate failed: %s", exc)
    return {"status": "ok"}
