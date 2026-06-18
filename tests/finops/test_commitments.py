"""Unit tests: commitment coverage & utilization math over a synthetic FOCUS set."""

from __future__ import annotations

from datetime import datetime, timezone

from cloudguardiq.core.enums import CloudProvider, Severity
from cloudguardiq.core.models import FindingResult, FocusCostRecord
from cloudguardiq.finops.commitments import (
    CommitmentCoverageSummary,
    compute_coverage,
    evaluate_commitments,
)

TENANT = "tenant-cc"
SUB = "sub-cc"


def _row(
    *,
    charge_category: str = "Usage",
    service_category: str = "Compute",
    effective_cost: float = 0.0,
    commitment_discount_id: str = "",
    day: int = 1,
) -> FocusCostRecord:
    start = datetime(2026, 5, day, tzinfo=timezone.utc)
    return FocusCostRecord(
        tenant_id=TENANT,
        billing_period="2026-05",
        charge_period_start=start,
        charge_period_end=start,
        charge_category=charge_category,
        effective_cost=effective_cost,
        sub_account_id=SUB,
        service_category=service_category,
        service_name="Virtual Machines",
        commitment_discount_id=commitment_discount_id,
    )


def _synthetic_set() -> list[FocusCostRecord]:
    # Eligible compute spend: 600 committed (under one commitment) + 400 on-demand
    # => coverage 60%. Commitment "ri-1" purchased at 1000 but only covers 600
    # => utilization 60%, 400 wasted.
    return [
        _row(commitment_discount_id="ri-1", effective_cost=600.0),
        _row(effective_cost=400.0),  # on-demand eligible
        _row(charge_category="Purchase", commitment_discount_id="ri-1",
             effective_cost=1000.0),
        # Storage usage is NOT commitment-eligible and must be ignored.
        _row(service_category="Storage", effective_cost=5000.0),
    ]


def test_compute_coverage_splits_committed_and_on_demand() -> None:
    summary = compute_coverage(_synthetic_set())
    assert isinstance(summary, CommitmentCoverageSummary)
    assert summary.committed_eligible_cost == 600.0
    assert summary.on_demand_eligible_cost == 400.0
    assert summary.eligible_cost == 1000.0
    assert summary.coverage_pct == 0.6
    # A single commitment "ri-1": purchased 1000, covered 600 -> 60% util.
    assert len(summary.commitments) == 1
    c = summary.commitments[0]
    assert c.commitment_discount_id == "ri-1"
    assert c.purchased_cost == 1000.0
    assert c.covered_usage_cost == 600.0
    assert c.utilization_pct == 0.6
    assert c.wasted_cost == 400.0
    assert summary.overall_utilization_pct == 0.6


def test_compute_coverage_empty_is_zeroed() -> None:
    summary = compute_coverage([])
    assert summary.coverage_pct == 0.0
    assert summary.eligible_cost == 0.0
    assert summary.commitments == []


def test_evaluate_commitments_emits_low_coverage_and_underutilized() -> None:
    findings = evaluate_commitments(
        _synthetic_set(),
        subscription_id=SUB,
        tenant_id=TENANT,
        provider=CloudProvider.AZURE,
    )
    by_rule = {f.rule_id: f for f in findings}
    assert "FIN-CC-001" in by_rule  # low coverage
    assert "FIN-CC-002" in by_rule  # under-utilized commitment

    low = by_rule["FIN-CC-001"]
    assert low.finding_type.value == "FINOPS"
    assert low.evidence["coverage_pct"] == 0.6
    assert low.evidence["on_demand_eligible_cost"] == 400.0
    # No linked recommendations -> estimated savings off the on-demand spend.
    assert low.finops_method == "ESTIMATED"
    assert low.estimated_impact_monthly_usd > 0.0

    under = by_rule["FIN-CC-002"]
    assert under.evidence["commitment_discount_id"] == "ri-1"
    assert under.estimated_impact_monthly_usd == 400.0  # wasted cost
    assert under.finops_method == "DIRECT"


def test_evaluate_commitments_links_purchase_recommendation_savings() -> None:
    rec = FindingResult(
        rule_id="REC-AZ-BENEFIT",
        rule_name="Azure benefit recommendation",
        severity=Severity.MEDIUM,
        estimated_impact_monthly_usd=150.0,
        finops_method="DIRECT",
        finops_confidence="HIGH",
        evidence={"recommendation_id": "/benefit/1"},
    )
    findings = evaluate_commitments(
        _synthetic_set(),
        subscription_id=SUB,
        tenant_id=TENANT,
        recommendations=[rec],
    )
    low = next(f for f in findings if f.rule_id == "FIN-CC-001")
    # Savings now come from the linked purchase recommendation (DIRECT).
    assert low.estimated_impact_monthly_usd == 150.0
    assert low.finops_method == "DIRECT"
    assert "/benefit/1" in low.evidence["linked_recommendation_ids"]


def test_evaluate_commitments_no_findings_when_fully_covered() -> None:
    rows = [
        _row(commitment_discount_id="ri-1", effective_cost=1000.0),
        _row(charge_category="Purchase", commitment_discount_id="ri-1",
             effective_cost=1000.0),
    ]
    assert evaluate_commitments(rows, subscription_id=SUB, tenant_id=TENANT) == []
