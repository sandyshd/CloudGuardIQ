"""Commitment-coverage & utilization analysis over FOCUS cost records.

Pure functions only: every routine here operates on
:class:`~cloudguardiq.core.models.FocusCostRecord` models. This layer imports
**no cloud SDK** and performs no I/O -- it is the FinOps analytics seam that
turns normalized billing rows into coverage/utilization metrics and
:class:`~cloudguardiq.core.models.FindingResult` objects.

Coverage answers "how much of my commitment-eligible spend is actually covered
by a Reservation / Savings Plan / CUD?". Utilization answers "of the
commitments I already bought, how much am I actually consuming?". Low coverage
and under-utilized commitments are each surfaced as FinOps findings with an
estimated monthly impact -- linked to Phase-3 purchase recommendations when
available.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence

from pydantic import BaseModel, Field

from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import FindingResult, FocusCostRecord, ResourceSnapshot

# Service categories eligible for commitment-based discounts (lower-cased).
DEFAULT_ELIGIBLE_CATEGORIES: frozenset[str] = frozenset({"compute"})

# Default thresholds (tunable by callers).
DEFAULT_COVERAGE_TARGET = 0.80  # warn below 80% commitment coverage
DEFAULT_UTILIZATION_FLOOR = 0.85  # warn below 85% commitment utilization
DEFAULT_ASSUMED_DISCOUNT = 0.25  # fallback savings rate for low coverage

# Recommendation rule-id fragments that represent a *purchase* recommendation
# (Reservation / Savings Plan / CUD / Azure benefit), used to link Phase-3
# savings to a low-coverage finding.
_PURCHASE_REC_KEYWORDS = ("RESERVATION", "SAVINGS", "BENEFIT", "CUD")

# Rule identifiers for the findings this module emits.
RULE_LOW_COVERAGE = "FIN-CC-001"
RULE_UNDER_UTILIZED = "FIN-CC-002"


class CommitmentUtilization(BaseModel):
    """Per-commitment purchase vs. consumption breakdown."""

    commitment_discount_id: str
    purchased_cost: float = 0.0
    covered_usage_cost: float = 0.0
    utilization_pct: float = 0.0
    wasted_cost: float = 0.0


class CommitmentCoverageSummary(BaseModel):
    """Account-level commitment coverage and utilization roll-up."""

    committed_eligible_cost: float = 0.0
    on_demand_eligible_cost: float = 0.0
    eligible_cost: float = 0.0
    coverage_pct: float = 0.0
    total_purchased_cost: float = 0.0
    total_covered_usage_cost: float = 0.0
    overall_utilization_pct: float = 0.0
    commitments: list[CommitmentUtilization] = Field(default_factory=list)


def _is_eligible(record: FocusCostRecord, eligible: frozenset[str]) -> bool:
    """Return True when the row's service category supports commitments."""
    return record.service_category.lower() in eligible


def compute_coverage(
    records: Iterable[FocusCostRecord],
    *,
    eligible_categories: Iterable[str] = DEFAULT_ELIGIBLE_CATEGORIES,
) -> CommitmentCoverageSummary:
    """Compute commitment coverage and per-commitment utilization.

    ``Usage`` rows carrying a ``commitment_discount_id`` count as committed
    spend; eligible ``Usage`` rows without one count as on-demand-eligible.
    ``Purchase`` rows carrying a ``commitment_discount_id`` represent the
    amortized amount paid for that commitment. Coverage is committed / (
    committed + on-demand-eligible); utilization is covered-usage / purchased.
    """
    eligible = frozenset(c.lower() for c in eligible_categories)
    committed_eligible = 0.0
    on_demand_eligible = 0.0
    purchased: dict[str, float] = defaultdict(float)
    covered: dict[str, float] = defaultdict(float)

    for record in records:
        category = record.charge_category.lower()
        if category == "purchase" and record.commitment_discount_id:
            purchased[record.commitment_discount_id] += record.effective_cost
            continue
        if not _is_eligible(record, eligible):
            continue
        if record.commitment_discount_id:
            committed_eligible += record.effective_cost
            covered[record.commitment_discount_id] += record.effective_cost
        else:
            on_demand_eligible += record.effective_cost

    eligible_cost = committed_eligible + on_demand_eligible
    coverage_pct = committed_eligible / eligible_cost if eligible_cost > 0 else 0.0

    commitments: list[CommitmentUtilization] = []
    total_purchased = 0.0
    total_covered = 0.0
    for cid in sorted(set(purchased) | set(covered)):
        paid = purchased.get(cid, 0.0)
        used = covered.get(cid, 0.0)
        utilization = used / paid if paid > 0 else 0.0
        total_purchased += paid
        total_covered += used
        commitments.append(
            CommitmentUtilization(
                commitment_discount_id=cid,
                purchased_cost=round(paid, 2),
                covered_usage_cost=round(used, 2),
                utilization_pct=round(utilization, 4),
                wasted_cost=round(max(paid - used, 0.0), 2),
            )
        )

    overall_util = total_covered / total_purchased if total_purchased > 0 else 0.0
    return CommitmentCoverageSummary(
        committed_eligible_cost=round(committed_eligible, 2),
        on_demand_eligible_cost=round(on_demand_eligible, 2),
        eligible_cost=round(eligible_cost, 2),
        coverage_pct=round(coverage_pct, 4),
        total_purchased_cost=round(total_purchased, 2),
        total_covered_usage_cost=round(total_covered, 2),
        overall_utilization_pct=round(overall_util, 4),
        commitments=commitments,
    )


def _purchase_recommendations(
    recommendations: Sequence[FindingResult],
) -> list[FindingResult]:
    """Filter to commitment *purchase* recommendations (no resource overlap)."""
    matched: list[FindingResult] = []
    for finding in recommendations:
        if "native_rule_overlap" in finding.evidence:
            continue
        rule_id = finding.rule_id.upper()
        if any(keyword in rule_id for keyword in _PURCHASE_REC_KEYWORDS):
            matched.append(finding)
    return matched


def _build_finding(
    *,
    rule_id: str,
    rule_name: str,
    provider: CloudProvider,
    subscription_id: str,
    tenant_id: str,
    resource_name: str,
    description: str,
    estimated_impact: float,
    finops_method: str,
    finops_confidence: str,
    severity: Severity,
    evidence: dict[str, object],
) -> FindingResult:
    """Build a commitment FinOps FindingResult with a deterministic id."""
    snapshot = ResourceSnapshot(
        provider=provider,
        subscription_id=subscription_id,
        resource_group="",
        resource_type="finops/commitment",
        resource_name=resource_name,
        region="",
        tenant_id=tenant_id,
        data_tier=DataTier.TIER1_NATIVE,
    )
    return FindingResult(
        tenant_id=tenant_id,
        resource_snapshot=snapshot,
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        finding_type=FindingType.FINOPS,
        description=description,
        evidence=evidence,
        estimated_impact_monthly_usd=round(estimated_impact, 2),
        finops_method=finops_method,
        finops_confidence=finops_confidence,
    )


def evaluate_commitments(
    records: Iterable[FocusCostRecord],
    *,
    subscription_id: str = "",
    tenant_id: str = "",
    provider: CloudProvider = CloudProvider.AZURE,
    eligible_categories: Iterable[str] = DEFAULT_ELIGIBLE_CATEGORIES,
    coverage_target: float = DEFAULT_COVERAGE_TARGET,
    utilization_floor: float = DEFAULT_UTILIZATION_FLOOR,
    assumed_discount: float = DEFAULT_ASSUMED_DISCOUNT,
    recommendations: Sequence[FindingResult] | None = None,
) -> list[FindingResult]:
    """Emit findings for low coverage and under-utilized commitments.

    Low-coverage savings link to Phase-3 purchase recommendations when
    supplied (``finops_method="DIRECT"``); otherwise they fall back to an
    estimate of ``on_demand_eligible_cost * assumed_discount``. Under-utilized
    commitment savings are the measured wasted (paid-but-unused) cost.
    """
    summary = compute_coverage(records, eligible_categories=eligible_categories)
    findings: list[FindingResult] = []

    if summary.on_demand_eligible_cost > 0 and summary.coverage_pct < coverage_target:
        linked = _purchase_recommendations(recommendations or [])
        linked_savings = sum(f.estimated_impact_monthly_usd for f in linked)
        linked_ids = [
            str(f.evidence.get("recommendation_id", ""))
            for f in linked
            if f.evidence.get("recommendation_id")
        ]
        if linked_savings > 0:
            estimated = linked_savings
            method, confidence = "DIRECT", "HIGH"
        else:
            estimated = summary.on_demand_eligible_cost * assumed_discount
            method, confidence = "ESTIMATED", "MEDIUM"
        gap = coverage_target - summary.coverage_pct
        findings.append(
            _build_finding(
                rule_id=RULE_LOW_COVERAGE,
                rule_name="Low commitment coverage",
                provider=provider,
                subscription_id=subscription_id,
                tenant_id=tenant_id,
                resource_name="commitment-coverage",
                description=(
                    "Commitment coverage of "
                    f"{summary.coverage_pct:.0%} is below the "
                    f"{coverage_target:.0%} target; "
                    f"${summary.on_demand_eligible_cost:,.2f} of eligible spend "
                    "is still on-demand."
                ),
                estimated_impact=estimated,
                finops_method=method,
                finops_confidence=confidence,
                severity=Severity.HIGH if gap >= 0.25 else Severity.MEDIUM,
                evidence={
                    "coverage_pct": summary.coverage_pct,
                    "coverage_target": coverage_target,
                    "committed_eligible_cost": summary.committed_eligible_cost,
                    "on_demand_eligible_cost": summary.on_demand_eligible_cost,
                    "linked_recommendation_ids": linked_ids,
                },
            )
        )

    for commitment in summary.commitments:
        if (
            commitment.purchased_cost > 0
            and commitment.utilization_pct < utilization_floor
        ):
            findings.append(
                _build_finding(
                    rule_id=RULE_UNDER_UTILIZED,
                    rule_name="Under-utilized commitment",
                    provider=provider,
                    subscription_id=subscription_id,
                    tenant_id=tenant_id,
                    resource_name=commitment.commitment_discount_id,
                    description=(
                        f"Commitment {commitment.commitment_discount_id} is "
                        f"{commitment.utilization_pct:.0%} utilized; "
                        f"${commitment.wasted_cost:,.2f}/mo is paid but unused."
                    ),
                    estimated_impact=commitment.wasted_cost,
                    finops_method="DIRECT",
                    finops_confidence="HIGH",
                    severity=(
                        Severity.HIGH
                        if commitment.utilization_pct < 0.5
                        else Severity.MEDIUM
                    ),
                    evidence={
                        "commitment_discount_id": commitment.commitment_discount_id,
                        "utilization_pct": commitment.utilization_pct,
                        "utilization_floor": utilization_floor,
                        "purchased_cost": commitment.purchased_cost,
                        "covered_usage_cost": commitment.covered_usage_cost,
                    },
                )
            )

    return findings
