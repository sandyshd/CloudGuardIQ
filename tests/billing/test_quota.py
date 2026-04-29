"""Tests for cloudguardiq.billing.quota (Phase 2.5 shared helper)."""

from __future__ import annotations

import pytest

from cloudguardiq.billing.plans import UNLIMITED
from cloudguardiq.billing.quota import check_ai_quota, record_ai_remediation
from cloudguardiq.billing.repository import BillingCustomer, BillingRepository
from cloudguardiq.billing.usage import UsageRepository
from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import SubscriptionTier


def _repos() -> tuple[BillingRepository, UsageRepository]:
    settings = Settings()
    return BillingRepository(settings), UsageRepository(settings)


@pytest.mark.asyncio
async def test_unknown_tenant_defaults_to_free_and_allowed() -> None:
    billing, usage = _repos()
    quota = await check_ai_quota(
        "tenant-new", billing_repo=billing, usage_repo=usage,
    )
    assert quota.allowed is True
    assert quota.tier == SubscriptionTier.FREE
    assert quota.cap == 5  # FREE plan from catalog
    assert quota.current == 0


@pytest.mark.asyncio
async def test_free_blocked_at_cap() -> None:
    billing, usage = _repos()
    for _ in range(5):
        await usage.increment_ai_remediations("tenant-free")
    quota = await check_ai_quota(
        "tenant-free", billing_repo=billing, usage_repo=usage,
    )
    assert quota.allowed is False
    assert quota.current == 5
    detail = quota.to_detail()
    assert detail["error"] == "upgrade_required"
    assert detail["limit"] == "ai_remediations_per_month"
    assert detail["current_tier"] == "free"


@pytest.mark.asyncio
async def test_pro_higher_cap_allows_more() -> None:
    billing, usage = _repos()
    await billing.upsert(BillingCustomer(
        tenant_id="tenant-pro", tier=SubscriptionTier.PRO,
    ))
    for _ in range(50):
        await usage.increment_ai_remediations("tenant-pro")
    quota = await check_ai_quota(
        "tenant-pro", billing_repo=billing, usage_repo=usage,
    )
    assert quota.allowed is True  # PRO cap = 100
    assert quota.cap == 100


@pytest.mark.asyncio
async def test_enterprise_unlimited() -> None:
    billing, usage = _repos()
    await billing.upsert(BillingCustomer(
        tenant_id="tenant-ent", tier=SubscriptionTier.ENTERPRISE,
    ))
    for _ in range(10000):
        await usage.increment_ai_remediations("tenant-ent")
    quota = await check_ai_quota(
        "tenant-ent", billing_repo=billing, usage_repo=usage,
    )
    assert quota.allowed is True
    assert quota.cap == UNLIMITED


@pytest.mark.asyncio
async def test_record_ai_remediation_increments() -> None:
    _, usage = _repos()
    await record_ai_remediation("tenant-x", usage_repo=usage)
    await record_ai_remediation("tenant-x", usage_repo=usage)
    rec = await usage.get_current("tenant-x")
    assert rec.ai_remediations == 2
