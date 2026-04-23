"""CloudGuardIQ -- Stripe billing service.

Wraps the `stripe` SDK with async-friendly helpers. All outbound Stripe calls
are dispatched to a worker thread via ``asyncio.to_thread`` so FastAPI handlers
remain non-blocking. The module is safe to import even when the ``stripe``
package is not installed -- any method call will raise a clear error.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from cloudguardiq.core.config import Settings, get_settings
from cloudguardiq.core.enums import SubscriptionTier

logger = logging.getLogger(__name__)

try:
    import stripe as _stripe  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - optional dependency
    _stripe = None  # type: ignore[assignment]


class StripeServiceError(RuntimeError):
    """Raised when the Stripe service cannot complete an operation."""


def _require_stripe() -> Any:
    """Return the imported ``stripe`` module or raise a clear error."""
    if _stripe is None:
        raise StripeServiceError(
            "The 'stripe' package is not installed. "
            "Install with: pip install stripe",
        )
    return _stripe


class StripeService:
    """Service facade over the Stripe SDK."""

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialise the service using :class:`Settings`."""
        self._settings = settings or get_settings()
        if _stripe is not None and self._settings.stripe_api_key:
            _stripe.api_key = self._settings.stripe_api_key

    # ------------------------------------------------------------------
    # Tier <-> price mapping
    # ------------------------------------------------------------------
    def price_id_for_tier(self, tier: SubscriptionTier) -> str:
        """Return the Stripe price id configured for *tier*."""
        mapping = {
            SubscriptionTier.FREE: self._settings.stripe_price_free,
            SubscriptionTier.PRO: self._settings.stripe_price_pro,
            SubscriptionTier.ENTERPRISE: self._settings.stripe_price_enterprise,
        }
        price = mapping.get(tier, "")
        if not price:
            raise StripeServiceError(
                f"No Stripe price id configured for tier {tier.value}",
            )
        return price

    def tier_for_price_id(self, price_id: str) -> SubscriptionTier:
        """Return the :class:`SubscriptionTier` that matches *price_id*."""
        if price_id == self._settings.stripe_price_enterprise:
            return SubscriptionTier.ENTERPRISE
        if price_id == self._settings.stripe_price_pro:
            return SubscriptionTier.PRO
        return SubscriptionTier.FREE

    # ------------------------------------------------------------------
    # Customer
    # ------------------------------------------------------------------
    async def ensure_customer(
        self,
        *,
        tenant_id: str,
        email: str | None = None,
        existing_customer_id: str | None = None,
    ) -> str:
        """Return a Stripe customer id, creating one if needed."""
        stripe = _require_stripe()
        if existing_customer_id:
            return existing_customer_id
        try:
            customer = await asyncio.to_thread(
                stripe.Customer.create,
                email=email,
                metadata={"tenant_id": tenant_id},
            )
        except Exception as exc:  # pragma: no cover - network failure path
            logger.warning("Stripe customer creation failed: %s", exc)
            raise StripeServiceError("Stripe customer creation failed") from exc
        return str(customer["id"])

    # ------------------------------------------------------------------
    # Checkout
    # ------------------------------------------------------------------
    async def create_checkout_session(
        self,
        *,
        customer_id: str,
        price_id: str,
        success_url: str | None = None,
        cancel_url: str | None = None,
    ) -> str:
        """Create a Stripe Checkout session and return its URL."""
        stripe = _require_stripe()
        try:
            session = await asyncio.to_thread(
                stripe.checkout.Session.create,
                customer=customer_id,
                mode="subscription",
                line_items=[{"price": price_id, "quantity": 1}],
                success_url=success_url or self._settings.stripe_success_url,
                cancel_url=cancel_url or self._settings.stripe_cancel_url,
            )
        except Exception as exc:
            logger.warning("Stripe checkout session creation failed: %s", exc)
            raise StripeServiceError(
                "Could not create Stripe checkout session",
            ) from exc
        url = session.get("url") if isinstance(session, dict) else getattr(
            session, "url", None,
        )
        if not url:
            raise StripeServiceError("Stripe returned no checkout URL")
        return str(url)

    # ------------------------------------------------------------------
    # Subscription status
    # ------------------------------------------------------------------
    async def get_subscription_status(
        self, customer_id: str,
    ) -> SubscriptionTier:
        """Return the active :class:`SubscriptionTier` for *customer_id*."""
        stripe = _require_stripe()
        try:
            result = await asyncio.to_thread(
                stripe.Subscription.list,
                customer=customer_id,
                status="active",
                limit=1,
            )
        except Exception as exc:
            logger.warning("Stripe subscription lookup failed: %s", exc)
            return SubscriptionTier.FREE

        data = result.get("data") if isinstance(result, dict) else getattr(
            result, "data", [],
        )
        if not data:
            return SubscriptionTier.FREE
        sub = data[0]
        items = (
            sub.get("items", {}).get("data", [])
            if isinstance(sub, dict)
            else getattr(sub, "items", {}).get("data", [])
        )
        if not items:
            return SubscriptionTier.FREE
        price = items[0].get("price", {}) if isinstance(items[0], dict) else {}
        price_id = price.get("id", "") if isinstance(price, dict) else ""
        return self.tier_for_price_id(price_id)

    # ------------------------------------------------------------------
    # Webhook verification
    # ------------------------------------------------------------------
    def verify_webhook(
        self,
        *,
        payload: bytes,
        signature: str,
    ) -> dict[str, Any]:
        """Verify a Stripe webhook signature and return the event dict."""
        stripe = _require_stripe()
        secret = self._settings.stripe_webhook_secret
        if not secret:
            raise StripeServiceError("Webhook secret is not configured")
        try:
            event = stripe.Webhook.construct_event(
                payload=payload,
                sig_header=signature,
                secret=secret,
            )
        except Exception as exc:
            logger.warning("Stripe webhook signature verification failed: %s", exc)
            raise StripeServiceError("Invalid webhook signature") from exc
        return dict(event) if not isinstance(event, dict) else event
