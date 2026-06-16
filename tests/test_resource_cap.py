"""Tests for tier-aware inventory resource cap (scan-layer enforcement)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from cloudguardiq.billing.repository import BillingCustomer, BillingRepository
from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import DataTier, SubscriptionTier
from cloudguardiq.core.models import ResourceSnapshot
from cloudguardiq.pipeline.resource_cap import cap_snapshots
from cloudguardiq.pipeline.scan_pipeline import ScanPipeline

_STORAGE = "Microsoft.Storage/storageAccounts"
_UNTYPED = "Microsoft.Foo/bars"
_COVERED = {_STORAGE.lower()}


def _snap(
    name: str,
    *,
    resource_type: str = _UNTYPED,
    cost: float = 0.0,
    tenant_id: str = "t1",
) -> ResourceSnapshot:
    return ResourceSnapshot(
        tenant_id=tenant_id,
        subscription_id="sub-1",
        resource_group="rg",
        resource_type=resource_type,
        resource_name=name,
        region="eastus",
        cost_monthly=cost,
        data_tier=DataTier.TIER1_NATIVE,
    )


# ---------------------------------------------------------------------------
# Pure cap_snapshots() unit tests
# ---------------------------------------------------------------------------


def test_unlimited_never_truncates() -> None:
    snaps = [_snap(f"r{i}") for i in range(5000)]
    kept, dropped = cap_snapshots(snaps, -1, covered_types=_COVERED)
    assert dropped == 0
    assert kept is snaps


def test_under_cap_returns_unchanged() -> None:
    snaps = [_snap(f"r{i}") for i in range(50)]
    kept, dropped = cap_snapshots(snaps, 100, covered_types=_COVERED)
    assert dropped == 0
    assert kept is snaps


def test_boundary_exactly_at_cap_not_truncated() -> None:
    snaps = [_snap(f"r{i}") for i in range(1000)]
    kept, dropped = cap_snapshots(snaps, 1000, covered_types=_COVERED)
    assert dropped == 0
    assert len(kept) == 1000


def test_rule_covered_resource_beats_costly_uncovered() -> None:
    """A covered resource outranks an uncovered one regardless of cost."""
    covered_cheap = _snap("covered", resource_type=_STORAGE, cost=0.0)
    uncovered_pricey = _snap("pricey", resource_type=_UNTYPED, cost=9_999.0)
    kept, dropped = cap_snapshots(
        [uncovered_pricey, covered_cheap], 1, covered_types=_COVERED,
    )
    assert dropped == 1
    assert kept[0].resource_name == "covered"


def test_cost_orders_within_same_coverage() -> None:
    cheap = _snap("cheap", resource_type=_UNTYPED, cost=1.0)
    pricey = _snap("pricey", resource_type=_UNTYPED, cost=500.0)
    kept, dropped = cap_snapshots(
        [cheap, pricey], 1, covered_types=_COVERED,
    )
    assert dropped == 1
    assert kept[0].resource_name == "pricey"


def test_stable_order_for_equal_keys() -> None:
    a = _snap("a", resource_type=_UNTYPED, cost=0.0)
    b = _snap("b", resource_type=_UNTYPED, cost=0.0)
    c = _snap("c", resource_type=_UNTYPED, cost=0.0)
    kept, dropped = cap_snapshots([a, b, c], 2, covered_types=_COVERED)
    assert [s.resource_name for s in kept] == ["a", "b"]
    assert dropped == 1


# ---------------------------------------------------------------------------
# Pipeline integration tests (tier resolution + truncation)
# ---------------------------------------------------------------------------


def _build_pipeline(
    snapshots: list[ResourceSnapshot],
    *,
    billing_repo: BillingRepository | None,
) -> tuple[ScanPipeline, dict[str, list[ResourceSnapshot]]]:
    adapter = MagicMock()
    adapter.scan = AsyncMock(return_value=snapshots)
    adapter.policy_findings = []

    captured: dict[str, list[ResourceSnapshot]] = {}

    def _evaluate(snaps: list[ResourceSnapshot]) -> list:
        captured["snaps"] = snaps
        return []

    policy = MagicMock()
    policy.evaluate.side_effect = _evaluate
    policy.covered_resource_types.return_value = set(_COVERED)

    db = MagicMock()
    db.save_finding = AsyncMock()
    db.save_scan_result = AsyncMock()
    db.mark_unseen_findings_resolved = AsyncMock()

    pipeline = ScanPipeline(
        adapter=adapter,
        policy_engine=policy,
        ai_engine=None,
        db=db,
        billing_repo=billing_repo,
    )
    return pipeline, captured


@pytest.mark.asyncio
async def test_free_tenant_capped_to_100_keeps_high_value() -> None:
    """FREE tenant with 150 resources -> exactly 100, costly storage kept."""
    settings = Settings()
    billing = BillingRepository(settings)  # no record -> defaults to FREE

    snaps = [_snap(f"cheap{i}") for i in range(149)]
    # A single high-cost, rule-covered storage account placed last.
    keeper = _snap("keepme", resource_type=_STORAGE, cost=5_000.0)
    snaps.append(keeper)

    pipeline, captured = _build_pipeline(snaps, billing_repo=billing)
    result = await pipeline.run("sub-1", tenant_id="t1")

    assert result.resources_scanned == 100
    kept_names = {s.resource_name for s in captured["snaps"]}
    assert "keepme" in kept_names  # high-value survives
    assert len(captured["snaps"]) == 100
    # 50 cheap untyped resources beyond the cap were dropped.
    assert len(kept_names) == 100


@pytest.mark.asyncio
async def test_enterprise_unlimited_no_truncation() -> None:
    settings = Settings()
    billing = BillingRepository(settings)
    await billing.upsert(
        BillingCustomer(tenant_id="t1", tier=SubscriptionTier.ENTERPRISE),
    )
    snaps = [_snap(f"r{i}") for i in range(5000)]
    pipeline, captured = _build_pipeline(snaps, billing_repo=billing)
    result = await pipeline.run("sub-1", tenant_id="t1")

    assert result.resources_scanned == 5000
    assert len(captured["snaps"]) == 5000


@pytest.mark.asyncio
async def test_pro_tenant_boundary_exactly_1000() -> None:
    settings = Settings()
    billing = BillingRepository(settings)
    await billing.upsert(
        BillingCustomer(tenant_id="t1", tier=SubscriptionTier.PRO),
    )
    snaps = [_snap(f"r{i}") for i in range(1000)]
    pipeline, captured = _build_pipeline(snaps, billing_repo=billing)
    result = await pipeline.run("sub-1", tenant_id="t1")

    assert result.resources_scanned == 1000
    assert len(captured["snaps"]) == 1000


@pytest.mark.asyncio
async def test_pro_tenant_over_boundary_truncates_to_1000() -> None:
    settings = Settings()
    billing = BillingRepository(settings)
    await billing.upsert(
        BillingCustomer(tenant_id="t1", tier=SubscriptionTier.PRO),
    )
    snaps = [_snap(f"r{i}") for i in range(1001)]
    pipeline, captured = _build_pipeline(snaps, billing_repo=billing)
    result = await pipeline.run("sub-1", tenant_id="t1")

    assert result.resources_scanned == 1000
    assert len(captured["snaps"]) == 1000
