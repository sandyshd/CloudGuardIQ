"""Pipeline-level tests: recommender findings merge via the unified path.

A DIRECT recommender supersedes the overlapping heuristic rule for the same
resource through the EXISTING ScanPipeline external-findings merge; a
non-overlapping recommendation is kept; and a recommender outage (graceful
``[]``) leaves the heuristic findings intact.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from cloudguardiq.adapters.recommenders.base import build_recommendation_finding
from cloudguardiq.core.enums import CloudProvider, DataTier, Severity
from cloudguardiq.core.models import ResourceSnapshot
from cloudguardiq.pipeline.scan_pipeline import ScanPipeline
from cloudguardiq.policy.engine import PolicyEngine


def _oversized_vm() -> ResourceSnapshot:
    """A VM that fires the FIN-005 heuristic (low CPU+mem, enough samples)."""
    return ResourceSnapshot(
        subscription_id="sub-1",
        resource_group="rg1",
        resource_type="Microsoft.Compute/virtualMachines",
        resource_name="vm-big",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        cost_monthly=200.0,
        config={
            "avg_cpu_7d": 5.0,
            "avg_memory_7d": 8.0,
            "metric_sample_count": 240,
            "metric_observation_days": 14,
        },
    )


def _recommender_finding(overlap: str = "FIN-005"):
    return build_recommendation_finding(
        rule_id="REC-AZ-ADVISOR-COST",
        rule_name="Azure Advisor cost recommendation",
        provider=CloudProvider.AZURE,
        subscription_id="sub-1",
        resource_group="rg1",
        resource_name="vm-big",
        resource_type="Microsoft.Compute/virtualMachines",
        region="eastus",
        monthly_savings=120.0,
        recommendation_id="/advisor/rec-1",
        native_rule_overlap=overlap,
        description="Right-size this VM.",
        severity=Severity.HIGH,
    )


def _make_adapter(recommender_findings: list) -> MagicMock:
    adapter = MagicMock()
    adapter.scan = AsyncMock(return_value=[_oversized_vm()])
    adapter.policy_findings = []
    adapter.defender_findings = []
    adapter.securityhub_findings = []
    adapter.scc_findings = []
    adapter.recommender_findings = recommender_findings
    return adapter


def _make_db() -> AsyncMock:
    db = AsyncMock()
    db.save_snapshot = AsyncMock(return_value="snap-id")
    db.save_finding = AsyncMock(return_value="finding-id")
    db.mark_unseen_findings_resolved = AsyncMock()
    return db


async def test_direct_recommender_supersedes_heuristic() -> None:
    adapter = _make_adapter([_recommender_finding("FIN-005")])
    pipeline = ScanPipeline(adapter, PolicyEngine(), MagicMock(), _make_db())
    with patch(
        "cloudguardiq.pipeline.scan_pipeline.refresh_prices", new=AsyncMock()
    ):
        await pipeline.run("sub-1")

    rule_ids = {f.rule_id for f in pipeline.last_findings}
    # The DIRECT recommendation is kept; the overlapping heuristic is dropped.
    assert "REC-AZ-ADVISOR-COST" in rule_ids
    assert "FIN-005" not in rule_ids


async def test_nonoverlapping_recommendation_is_kept() -> None:
    # A reservation-style recommendation with no native_rule_overlap.
    benefit = build_recommendation_finding(
        rule_id="REC-AZ-BENEFIT",
        rule_name="Azure benefit recommendation",
        provider=CloudProvider.AZURE,
        subscription_id="sub-1",
        resource_group="",
        resource_name="commitment",
        resource_type="Microsoft.CostManagement/benefitRecommendations",
        region="",
        monthly_savings=300.0,
        recommendation_id="/benefit/1",
    )
    adapter = _make_adapter([benefit])
    pipeline = ScanPipeline(adapter, PolicyEngine(), MagicMock(), _make_db())
    with patch(
        "cloudguardiq.pipeline.scan_pipeline.refresh_prices", new=AsyncMock()
    ):
        await pipeline.run("sub-1")

    rule_ids = {f.rule_id for f in pipeline.last_findings}
    assert "REC-AZ-BENEFIT" in rule_ids
    # Non-overlapping -> the heuristic still fires alongside it.
    assert "FIN-005" in rule_ids


async def test_recommender_failure_still_emits_heuristics() -> None:
    # Graceful failure surfaces as an empty recommender_findings list.
    adapter = _make_adapter([])
    pipeline = ScanPipeline(adapter, PolicyEngine(), MagicMock(), _make_db())
    with patch(
        "cloudguardiq.pipeline.scan_pipeline.refresh_prices", new=AsyncMock()
    ):
        await pipeline.run("sub-1")

    rule_ids = {f.rule_id for f in pipeline.last_findings}
    assert "FIN-005" in rule_ids
    assert "REC-AZ-ADVISOR-COST" not in rule_ids
