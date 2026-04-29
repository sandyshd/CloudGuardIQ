"""Tests for the plan catalog (cloudguardiq.billing.plans)."""

from __future__ import annotations

from cloudguardiq.billing.plans import (
    PLAN_CATALOG,
    UNLIMITED,
    all_plans,
    get_plan,
    is_unlimited,
)
from cloudguardiq.core.enums import SubscriptionTier


def test_catalog_has_all_three_tiers() -> None:
    assert set(PLAN_CATALOG.keys()) == {
        SubscriptionTier.FREE,
        SubscriptionTier.PRO,
        SubscriptionTier.ENTERPRISE,
    }


def test_all_plans_are_in_display_order() -> None:
    plans = all_plans()
    assert [p.tier for p in plans] == [
        SubscriptionTier.FREE,
        SubscriptionTier.PRO,
        SubscriptionTier.ENTERPRISE,
    ]


def test_get_plan_returns_correct_limits() -> None:
    free = get_plan(SubscriptionTier.FREE)
    starter = get_plan(SubscriptionTier.PRO)
    enterprise = get_plan(SubscriptionTier.ENTERPRISE)

    assert free.max_subscriptions == 1
    assert free.max_resources_per_scan == 100
    assert free.self_healing is False

    assert starter.max_subscriptions == 3
    assert starter.max_resources_per_scan == 1000
    assert starter.scan_frequency_minutes == 60

    assert enterprise.max_subscriptions == UNLIMITED
    assert enterprise.self_healing is True
    assert enterprise.priority_support is True


def test_features_never_mention_defender() -> None:
    """Plan features must be cloud-agnostic (Phase 1 architecture rule)."""
    for plan in all_plans():
        joined = " ".join(plan.features).lower()
        assert "defender" not in joined, (
            f"Plan '{plan.name}' must not reference Defender in marketing copy"
        )


def test_pricing_increases_monotonically() -> None:
    plans = all_plans()
    for earlier, later in zip(plans, plans[1:], strict=False):
        assert earlier.price_usd_monthly <= later.price_usd_monthly


def test_is_unlimited_helper() -> None:
    assert is_unlimited(UNLIMITED) is True
    assert is_unlimited(0) is False
    assert is_unlimited(100) is False

