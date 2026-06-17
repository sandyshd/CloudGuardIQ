"""CloudGuardIQ -- Subscription plan catalog (single source of truth).

Plan limits are defined here, intentionally decoupled from any specific cloud
vendor capability (e.g. Microsoft Defender for Cloud). Tiers are scaled on
*resources*, *cloud accounts/subscriptions*, *AI remediation usage*, and
*scan frequency* -- the same axes used by category-leading CSPM products
(Wiz, Orca, Prisma Cloud) and the only model that works for multi-cloud.

When Defender for Cloud (or an analogous vendor signal) is enabled on a
customer subscription we ENRICH findings with it automatically -- it is a
free capability uplift, never a paywall.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from cloudguardiq.core.enums import SubscriptionTier

if TYPE_CHECKING:
    from cloudguardiq.core.config import Settings

UNLIMITED: int = -1


class PlanLimits(BaseModel):
    """Concrete usage limits and feature flags for a single tier."""

    tier: SubscriptionTier
    name: str
    price_usd_monthly: int
    price_display: str
    cadence: str = "/mo"

    # Scale axes (use ``UNLIMITED`` for "no cap")
    max_subscriptions: int
    max_resources_per_scan: int
    max_ai_remediations_per_month: int
    scan_frequency_minutes: int  # smallest interval allowed (lower = better)

    # Capability flags
    self_healing: bool = False
    priority_support: bool = False

    # Marketing bullets shown in the UI (kept in sync with the limits above)
    features: list[str] = Field(default_factory=list)


def _free() -> PlanLimits:
    return PlanLimits(
        tier=SubscriptionTier.FREE,
        name="Free",
        price_usd_monthly=0,
        price_display="$0",
        max_subscriptions=1,
        max_resources_per_scan=100,
        max_ai_remediations_per_month=5,
        scan_frequency_minutes=1440,  # daily
        self_healing=False,
        priority_support=False,
        features=[
            "1 cloud subscription / account",
            "Up to 100 resources per scan",
            "Daily scans",
            "5 AI remediation plans / month",
            "Community support",
        ],
    )


def _starter() -> PlanLimits:
    return PlanLimits(
        tier=SubscriptionTier.PRO,
        name="Starter",
        price_usd_monthly=49,
        price_display="$49",
        max_subscriptions=3,
        max_resources_per_scan=1000,
        max_ai_remediations_per_month=100,
        scan_frequency_minutes=60,  # hourly
        self_healing=False,
        priority_support=False,
        features=[
            "Up to 3 cloud subscriptions / accounts",
            "Up to 1,000 resources per scan",
            "Hourly scans",
            "100 AI remediation plans / month",
            "Email support",
        ],
    )


def _enterprise() -> PlanLimits:
    return PlanLimits(
        tier=SubscriptionTier.ENTERPRISE,
        name="Enterprise",
        price_usd_monthly=299,
        price_display="$299",
        max_subscriptions=UNLIMITED,
        max_resources_per_scan=UNLIMITED,
        max_ai_remediations_per_month=UNLIMITED,
        scan_frequency_minutes=15,
        self_healing=True,
        priority_support=True,
        features=[
            "Unlimited subscriptions / accounts",
            "Unlimited resources per scan",
            "15-minute continuous scans",
            "Unlimited AI remediation plans",
            "Self-healing automation",
            "Priority SLA support",
        ],
    )


PLAN_CATALOG: dict[SubscriptionTier, PlanLimits] = {
    SubscriptionTier.FREE: _free(),
    SubscriptionTier.PRO: _starter(),
    SubscriptionTier.ENTERPRISE: _enterprise(),
}


def get_plan(tier: SubscriptionTier) -> PlanLimits:
    """Return the :class:`PlanLimits` for *tier* (defaults to FREE)."""
    return PLAN_CATALOG.get(tier, PLAN_CATALOG[SubscriptionTier.FREE])


def all_plans() -> list[PlanLimits]:
    """Return all plans in display order (FREE -> PRO -> ENTERPRISE)."""
    return [
        PLAN_CATALOG[SubscriptionTier.FREE],
        PLAN_CATALOG[SubscriptionTier.PRO],
        PLAN_CATALOG[SubscriptionTier.ENTERPRISE],
    ]


def is_unlimited(value: int) -> bool:
    """Return True when *value* represents an unlimited quota."""
    return value == UNLIMITED


def default_tier(settings: Settings) -> SubscriptionTier:
    """Return the tier assigned to tenants without a billing record.

    While Stripe billing is disabled the product runs without a paywall, so
    tenants default to ``settings.billing_default_tier`` (Enterprise) and can
    switch plans freely. When Stripe is enabled the default reverts to FREE
    so the paid tiers stay gated behind checkout.
    """
    if getattr(settings, "billing_stripe_enabled", False):
        return SubscriptionTier.FREE
    raw = getattr(settings, "billing_default_tier", SubscriptionTier.ENTERPRISE.value)
    try:
        return SubscriptionTier(raw)
    except ValueError:
        return SubscriptionTier.ENTERPRISE
