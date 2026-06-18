"""CloudGuardIQ -- native cloud cost-recommender seam.

Each cloud's first-party cost optimizer (Azure Advisor / Reservation &
Savings-Plan recommendations, AWS Cost Explorer & Compute Optimizer, GCP
Recommender) emits vendor-grade savings. A :class:`RecommenderProvider`
normalizes those into :class:`FindingResult` objects tagged
``finops_method="DIRECT"`` / ``finops_confidence="HIGH"`` so they surface
through the *existing* ScanPipeline external-findings merge -- superseding the
overlapping heuristic FinOps rule for the same resource.

This module imports **no cloud SDK**; concrete providers lazy-import their SDK
and accept injected clients for testing. Every public call is graceful: a
recommender failure logs a warning and yields ``[]`` so the heuristic rules
still run.
"""

from __future__ import annotations

import abc
import logging

from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

logger = logging.getLogger(__name__)


def _to_float(value: object) -> float:
    """Best-effort parse of a savings figure (handles str/Decimal/None)."""
    if value is None:
        return 0.0
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def build_recommendation_finding(
    *,
    rule_id: str,
    rule_name: str,
    provider: CloudProvider,
    subscription_id: str,
    resource_group: str,
    resource_name: str,
    resource_type: str,
    region: str,
    monthly_savings: float,
    recommendation_id: str,
    native_rule_overlap: str = "",
    description: str = "",
    severity: Severity = Severity.MEDIUM,
) -> FindingResult:
    """Normalize a native recommendation into a DIRECT FinOps FindingResult.

    The finding carries the evidence keys the pipeline's
    ``_dedupe_cloud_native_against_native`` reads -- ``resource_key``
    (``"resource_group/resource_name"`` lowercased) and, when the
    recommendation supersedes a heuristic rule, ``native_rule_overlap``
    (that rule's id, e.g. ``"FIN-005"``/``"VM-007"``) -- plus the native
    ``recommendation_id`` for traceability.
    """
    resource_key = f"{resource_group.lower()}/{resource_name.lower()}"
    snapshot = ResourceSnapshot(
        provider=provider,
        subscription_id=subscription_id,
        resource_group=resource_group,
        resource_type=resource_type,
        resource_name=resource_name,
        region=region,
        data_tier=DataTier.TIER1_NATIVE,
    )
    evidence: dict[str, object] = {
        "recommendation_id": recommendation_id,
        "resource_key": resource_key,
        "monthly_savings_usd": round(monthly_savings, 2),
    }
    if native_rule_overlap:
        evidence["native_rule_overlap"] = native_rule_overlap
    return FindingResult(
        resource_snapshot=snapshot,
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        finding_type=FindingType.FINOPS,
        description=description,
        evidence=evidence,
        estimated_impact_monthly_usd=round(monthly_savings, 2),
        finops_method="DIRECT",
        finops_confidence="HIGH",
    )


class RecommenderProvider(abc.ABC):
    """Provider-agnostic native cost-recommender source."""

    @abc.abstractmethod
    async def _fetch_recommendations(self, scope: str) -> list[FindingResult]:
        """Fetch native recommendations. Errors here are caught above."""

    async def get_recommendations(self, scope: str = "") -> list[FindingResult]:
        """Return normalized recommendations (best-effort; ``[]`` on error)."""
        try:
            return await self._fetch_recommendations(scope)
        except Exception:  # noqa: BLE001 -- recommenders must never crash a scan
            logger.warning(
                "%s recommender fetch failed -- continuing without native "
                "recommendations",
                type(self).__name__,
                exc_info=True,
            )
            return []


class NullRecommenderProvider(RecommenderProvider):
    """No-op provider (emits no recommendations)."""

    async def _fetch_recommendations(self, scope: str) -> list[FindingResult]:
        """Return no recommendations."""
        return []
