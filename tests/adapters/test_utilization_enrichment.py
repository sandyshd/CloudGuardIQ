"""Tests for utilization enrichment in the native scanner and end-to-end
activation of the idle/rightsizing FinOps rules through the scan pipeline."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from cloudguardiq.adapters.native_scanner import NativeScanner, _azure_arm_id
from cloudguardiq.adapters.rules.azure.compute import IdleVMRule
from cloudguardiq.billing.metrics_provider import ResourceUtilization
from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType
from cloudguardiq.core.models import ResourceSnapshot
from cloudguardiq.pipeline.scan_pipeline import ScanPipeline
from cloudguardiq.policy.engine import PolicyEngine


def _vm(name: str = "vm1", *, cost: float = 0.0, **config: object) -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id="sub-1",
        resource_group="rg",
        resource_type="Microsoft.Compute/virtualMachines",
        resource_name=name,
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        cost_monthly=cost,
        config=dict(config),
    )


async def test_enrich_utilization_stamps_metric_keys() -> None:
    scanner = NativeScanner(subscription_id="sub-1")
    snap = _vm(vm_size="Standard_D2s_v3")
    arm = _azure_arm_id(snap)
    util = ResourceUtilization(
        avg_cpu=3.0, p95_cpu=4.0, observation_days=10, sample_count=240
    )
    scanner._metrics_provider = MagicMock()
    scanner._metrics_provider.get_utilization = AsyncMock(return_value={arm: util})

    await scanner._enrich_utilization([snap])

    assert snap.config["avg_cpu_7d"] == 4.0
    assert snap.config["metric_sample_count"] == 240
    assert snap.config["metric_observation_days"] == 10
    assert snap.data_tier == DataTier.TIER2_ENRICHED


async def test_enrich_utilization_leaves_config_untouched_on_failure() -> None:
    scanner = NativeScanner(subscription_id="sub-1")
    snap = _vm(vm_size="Standard_D2s_v3")
    # Provider's graceful contract: returns {} on any error.
    scanner._metrics_provider = MagicMock()
    scanner._metrics_provider.get_utilization = AsyncMock(return_value={})

    await scanner._enrich_utilization([snap])

    assert "avg_cpu_7d" not in snap.config
    assert "metric_sample_count" not in snap.config


async def test_pipeline_completes_when_vm_has_no_metrics() -> None:
    snap = _vm(cost=100.0, vm_size="Standard_D2s_v3")  # no metric keys
    adapter = MagicMock()
    adapter.scan = AsyncMock(return_value=[snap])
    adapter.policy_findings = []
    adapter.defender_findings = []
    adapter.securityhub_findings = []
    adapter.scc_findings = []

    db = AsyncMock()
    db.save_snapshot = AsyncMock(return_value="snap-id")
    db.save_finding = AsyncMock(return_value="finding-id")
    db.mark_unseen_findings_resolved = AsyncMock()

    pipeline = ScanPipeline(adapter, PolicyEngine(), MagicMock(), db)
    with patch(
        "cloudguardiq.pipeline.scan_pipeline.refresh_prices", new=AsyncMock()
    ):
        await pipeline.run("sub-1")

    # No metrics stamped -> idle rule stays dormant.
    assert not any(f.rule_id == "VM-007" for f in pipeline.last_findings)


async def test_pipeline_emits_finops_finding_for_low_cpu_vm() -> None:
    snap = _vm(
        name="idle-vm",
        cost=120.0,
        avg_cpu_7d=2.0,
        metric_sample_count=240,
        metric_observation_days=10,
    )
    adapter = MagicMock()
    adapter.scan = AsyncMock(return_value=[snap])
    adapter.policy_findings = []
    adapter.defender_findings = []
    adapter.securityhub_findings = []
    adapter.scc_findings = []

    db = AsyncMock()
    db.save_snapshot = AsyncMock(return_value="snap-id")
    db.save_finding = AsyncMock(return_value="finding-id")
    db.mark_unseen_findings_resolved = AsyncMock()

    pipeline = ScanPipeline(adapter, PolicyEngine(), MagicMock(), db)
    with patch(
        "cloudguardiq.pipeline.scan_pipeline.refresh_prices", new=AsyncMock()
    ):
        await pipeline.run("sub-1")

    idle = [f for f in pipeline.last_findings if f.rule_id == "VM-007"]
    assert len(idle) == 1
    assert idle[0].finding_type == FindingType.FINOPS


def test_idle_rule_requires_sufficient_observation() -> None:
    rule = IdleVMRule()
    fires = _vm(
        cost=100.0,
        avg_cpu_7d=2.0,
        metric_sample_count=240,
        metric_observation_days=10,
    )
    assert rule.evaluate(fires) is not None

    too_short = _vm(
        cost=100.0,
        avg_cpu_7d=2.0,
        metric_sample_count=240,
        metric_observation_days=3,
    )
    assert rule.evaluate(too_short) is None

    too_few = _vm(
        cost=100.0,
        avg_cpu_7d=2.0,
        metric_sample_count=5,
        metric_observation_days=10,
    )
    assert rule.evaluate(too_few) is None

    no_metrics = _vm(cost=100.0, avg_cpu_7d=2.0)
    assert rule.evaluate(no_metrics) is None
