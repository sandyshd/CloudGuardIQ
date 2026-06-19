"""Shared finding-construction helper for the FinOps analytics layer.

Pure: builds :class:`~cloudguardiq.core.models.FindingResult` objects with a
deterministic id from a minimal :class:`ResourceSnapshot`. No cloud SDK, no I/O.
"""

from __future__ import annotations

from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


def build_finops_finding(
    *,
    rule_id: str,
    rule_name: str,
    provider: CloudProvider,
    subscription_id: str,
    tenant_id: str,
    resource_name: str,
    description: str,
    evidence: dict[str, object],
    estimated_impact_monthly_usd: float = 0.0,
    finops_method: str = "NONE",
    finops_confidence: str = "LOW",
    severity: Severity = Severity.MEDIUM,
) -> FindingResult:
    """Build a FinOps FindingResult with a deterministic, re-scan-stable id."""
    snapshot = ResourceSnapshot(
        provider=provider,
        subscription_id=subscription_id,
        resource_group="",
        resource_type="finops/governance",
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
        estimated_impact_monthly_usd=round(estimated_impact_monthly_usd, 2),
        finops_method=finops_method,
        finops_confidence=finops_confidence,
    )
