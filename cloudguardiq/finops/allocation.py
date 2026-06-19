"""Cost allocation (showback/chargeback) + tag-coverage governance.

Pure functions over :class:`~cloudguardiq.core.models.FocusCostRecord`. No
cloud SDK, no I/O. Groups spend by an allocation dimension (a tag/label such as
``team`` / ``app`` / ``environment`` / ``cost_center``), measures how much of
the spend is attributable (tag coverage), and emits a FinOps governance finding
for unallocated spend above a threshold -- generalizing the per-resource
``MissingCostTags`` rule into an account-level coverage metric.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from pydantic import BaseModel, Field

from cloudguardiq.core.enums import CloudProvider, Severity
from cloudguardiq.core.models import FindingResult, FocusCostRecord
from cloudguardiq.finops._common import build_finops_finding

# Allocation dimensions the platform understands out of the box. Each maps to
# one or more candidate tag keys (case-insensitive) so common spellings match.
DEFAULT_DIMENSIONS: tuple[str, ...] = ("team", "app", "environment", "cost_center")
_TAG_SYNONYMS: dict[str, tuple[str, ...]] = {
    "team": ("team", "team-name", "teamname"),
    "app": ("app", "application", "service-name", "app-name"),
    "environment": ("environment", "env"),
    "cost_center": ("cost_center", "cost-center", "costcenter", "costcentre"),
}

UNALLOCATED_KEY = "unallocated"
DEFAULT_COVERAGE_TARGET = 0.80
DEFAULT_MIN_UNALLOCATED_USD = 100.0

RULE_LOW_COVERAGE = "FIN-AL-001"


class AllocationGroup(BaseModel):
    """Spend attributed to one value of an allocation dimension."""

    key: str
    cost: float = 0.0
    pct: float = 0.0


class AllocationSummary(BaseModel):
    """Showback/chargeback roll-up for a single allocation dimension."""

    dimension: str
    total_cost: float = 0.0
    allocated_cost: float = 0.0
    unallocated_cost: float = 0.0
    coverage_pct: float = 0.0
    groups: list[AllocationGroup] = Field(default_factory=list)


def _candidate_keys(dimension: str) -> tuple[str, ...]:
    """Return the candidate tag keys (lower-cased) for an allocation dimension."""
    return _TAG_SYNONYMS.get(dimension, (dimension,))


def _tag_value(record: FocusCostRecord, dimension: str) -> str | None:
    """Return the allocation value for ``record`` under ``dimension`` or None."""
    lowered = {k.lower(): v for k, v in record.tags.items()}
    for candidate in _candidate_keys(dimension):
        value = lowered.get(candidate)
        if value:
            return value
    return None


def allocate_spend(
    records: Iterable[FocusCostRecord], *, dimension: str
) -> AllocationSummary:
    """Group effective spend by the allocation ``dimension``'s tag value.

    Rows missing the tag contribute to ``unallocated_cost``. Returns groups
    for tagged values only (sorted by cost descending); the unallocated bucket
    is exposed separately so callers can render it distinctly.
    """
    grouped: dict[str, float] = defaultdict(float)
    unallocated = 0.0
    total = 0.0
    for record in records:
        cost = record.effective_cost
        total += cost
        value = _tag_value(record, dimension)
        if value is None:
            unallocated += cost
        else:
            grouped[value] += cost

    allocated = total - unallocated
    coverage = allocated / total if total > 0 else 0.0
    groups = sorted(
        (
            AllocationGroup(
                key=key,
                cost=round(cost, 2),
                pct=round(cost / total, 4) if total > 0 else 0.0,
            )
            for key, cost in grouped.items()
        ),
        key=lambda g: g.cost,
        reverse=True,
    )
    return AllocationSummary(
        dimension=dimension,
        total_cost=round(total, 2),
        allocated_cost=round(allocated, 2),
        unallocated_cost=round(unallocated, 2),
        coverage_pct=round(coverage, 4),
        groups=groups,
    )


def compute_tag_coverage(
    records: Iterable[FocusCostRecord],
    *,
    dimensions: Iterable[str] = DEFAULT_DIMENSIONS,
) -> dict[str, float]:
    """Return cost-weighted tag-coverage % for each allocation dimension."""
    materialized = list(records)
    total = sum(r.effective_cost for r in materialized)
    coverage: dict[str, float] = {}
    for dimension in dimensions:
        if total <= 0:
            coverage[dimension] = 0.0
            continue
        tagged = sum(
            r.effective_cost
            for r in materialized
            if _tag_value(r, dimension) is not None
        )
        coverage[dimension] = round(tagged / total, 4)
    return coverage


def evaluate_allocation(
    records: Iterable[FocusCostRecord],
    *,
    subscription_id: str = "",
    tenant_id: str = "",
    provider: CloudProvider = CloudProvider.AZURE,
    dimensions: Iterable[str] = DEFAULT_DIMENSIONS,
    coverage_target: float = DEFAULT_COVERAGE_TARGET,
    min_unallocated_usd: float = DEFAULT_MIN_UNALLOCATED_USD,
) -> list[FindingResult]:
    """Emit a governance finding per dimension with poor tag coverage.

    A finding is raised when coverage is below ``coverage_target`` *and* the
    unallocated spend exceeds ``min_unallocated_usd``. These are governance
    findings (no direct savings) so ``estimated_impact_monthly_usd`` is 0.
    """
    materialized = list(records)
    findings: list[FindingResult] = []
    for dimension in dimensions:
        summary = allocate_spend(materialized, dimension=dimension)
        if (
            summary.coverage_pct < coverage_target
            and summary.unallocated_cost >= min_unallocated_usd
        ):
            findings.append(
                build_finops_finding(
                    rule_id=RULE_LOW_COVERAGE,
                    rule_name="Low cost-allocation tag coverage",
                    provider=provider,
                    subscription_id=subscription_id,
                    tenant_id=tenant_id,
                    resource_name=f"allocation/{dimension}",
                    description=(
                        f"Only {summary.coverage_pct:.0%} of spend is attributed "
                        f"to a '{dimension}'; "
                        f"${summary.unallocated_cost:,.2f}/mo is unallocated and "
                        "cannot be charged back."
                    ),
                    evidence={
                        "dimension": dimension,
                        "coverage_pct": summary.coverage_pct,
                        "coverage_target": coverage_target,
                        "unallocated_cost": summary.unallocated_cost,
                        "total_cost": summary.total_cost,
                    },
                    severity=(
                        Severity.MEDIUM
                        if summary.coverage_pct < 0.5
                        else Severity.LOW
                    ),
                )
            )
    return findings
