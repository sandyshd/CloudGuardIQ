"""Unit tests: cost allocation grouping + tag-coverage governance."""

from __future__ import annotations

from datetime import datetime, timezone

from cloudguardiq.core.enums import CloudProvider
from cloudguardiq.core.models import FocusCostRecord
from cloudguardiq.finops.allocation import (
    AllocationSummary,
    allocate_spend,
    compute_tag_coverage,
    evaluate_allocation,
)

TENANT = "tenant-al"
SUB = "sub-al"


def _row(cost: float, tags: dict[str, str] | None = None) -> FocusCostRecord:
    start = datetime(2026, 5, 1, tzinfo=timezone.utc)
    return FocusCostRecord(
        tenant_id=TENANT,
        billing_period="2026-05",
        charge_period_start=start,
        charge_period_end=start,
        charge_category="Usage",
        effective_cost=cost,
        sub_account_id=SUB,
        service_category="Compute",
        tags=tags or {},
    )


def _mixed_set() -> list[FocusCostRecord]:
    # team tag present on $700 of $1000 => 70% coverage, $300 unallocated.
    return [
        _row(400.0, {"team": "data"}),
        _row(300.0, {"team": "platform"}),
        _row(300.0),  # untagged
    ]


def test_allocate_spend_groups_by_tag_value() -> None:
    summary = allocate_spend(_mixed_set(), dimension="team")
    assert isinstance(summary, AllocationSummary)
    assert summary.total_cost == 1000.0
    assert summary.allocated_cost == 700.0
    assert summary.unallocated_cost == 300.0
    assert summary.coverage_pct == 0.7
    groups = {g.key: g for g in summary.groups}
    assert groups["data"].cost == 400.0
    assert abs(groups["data"].pct - 0.4) < 1e-9
    assert groups["platform"].cost == 300.0
    # Groups are sorted by cost descending.
    assert summary.groups[0].cost >= summary.groups[-1].cost


def test_compute_tag_coverage_per_dimension() -> None:
    records = [
        _row(500.0, {"team": "data", "environment": "prod"}),
        _row(500.0, {"team": "data"}),  # no environment tag
    ]
    coverage = compute_tag_coverage(records, dimensions=["team", "environment"])
    assert coverage["team"] == 1.0
    assert coverage["environment"] == 0.5


def test_compute_tag_coverage_empty_is_zero() -> None:
    assert compute_tag_coverage([], dimensions=["team"]) == {"team": 0.0}


def test_evaluate_allocation_emits_finding_below_target() -> None:
    findings = evaluate_allocation(
        _mixed_set(),
        subscription_id=SUB,
        tenant_id=TENANT,
        dimensions=["team"],
        coverage_target=0.80,
        min_unallocated_usd=50.0,
        provider=CloudProvider.AZURE,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "FIN-AL-001"
    assert f.finding_type.value == "FINOPS"
    assert f.evidence["dimension"] == "team"
    assert f.evidence["coverage_pct"] == 0.7
    assert f.evidence["unallocated_cost"] == 300.0
    assert f.estimated_impact_monthly_usd == 0.0  # governance, not savings


def test_evaluate_allocation_no_finding_when_well_tagged() -> None:
    records = [_row(1000.0, {"team": "data"})]
    findings = evaluate_allocation(
        records,
        subscription_id=SUB,
        tenant_id=TENANT,
        dimensions=["team"],
        coverage_target=0.80,
    )
    assert findings == []


def test_evaluate_allocation_skips_tiny_unallocated() -> None:
    records = [_row(990.0, {"team": "data"}), _row(10.0)]
    findings = evaluate_allocation(
        records,
        subscription_id=SUB,
        tenant_id=TENANT,
        dimensions=["team"],
        coverage_target=0.999,
        min_unallocated_usd=50.0,
    )
    assert findings == []
