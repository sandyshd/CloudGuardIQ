"""Tests for FinOps confidence/method labeling (Prompt 0 bug fix 2).

Direct idle-resource rules (FIN-001/002/003) must report finops_method=DIRECT
and finops_confidence=HIGH. Heuristic estimate rules (FIN-004..008) must report
finops_method=ESTIMATED and finops_confidence=MEDIUM, populating
estimated_impact_monthly_usd (not waste_monthly_usd).
"""

from __future__ import annotations

from cloudguardiq.adapters.rules.azure.finops import (
    AKSNoAutoscalerRule,
    AppGatewayLowUtilisationRule,
    DevTestOutsideBusinessHoursRule,
    EmptyLoadBalancerRule,
    HotTierBlobNotAccessedRule,
    OversizedVMRule,
    UnattachedManagedDiskRule,
)
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import ResourceSnapshot


def _snap(resource_type, *, config=None, tags=None, cost_monthly=100.0):
    return ResourceSnapshot(
        subscription_id="sub-test",
        resource_group="rg-test",
        resource_type=resource_type,
        resource_name="res-test",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config=config or {},
        tags=tags or {},
        cost_monthly=cost_monthly,
    )


class TestDirectRulesAreHighConfidence:
    def test_unattached_disk_is_direct_high(self):
        snap = _snap(
            "Microsoft.Compute/disks",
            config={"disk_state": "Unattached"},
            cost_monthly=38.40,
        )
        finding = UnattachedManagedDiskRule().evaluate(snap)
        assert finding is not None
        assert finding.finops_method == "DIRECT"
        assert finding.finops_confidence == "HIGH"
        assert finding.waste_monthly_usd == 38.40

    def test_empty_lb_is_direct_high(self):
        snap = _snap(
            "Microsoft.Network/loadBalancers",
            config={"backend_pool_count": 0},
            cost_monthly=18.25,
        )
        finding = EmptyLoadBalancerRule().evaluate(snap)
        assert finding is not None
        assert finding.finops_method == "DIRECT"
        assert finding.finops_confidence == "HIGH"
        assert finding.waste_monthly_usd == 18.25


class TestHeuristicRulesAreEstimatedMedium:
    def test_oversized_vm_is_estimated_medium(self):
        snap = _snap(
            "Microsoft.Compute/virtualMachines",
            config={"avg_cpu_7d": 5.0, "avg_memory_7d": 8.0, "metric_sample_count": 240, "metric_observation_days": 14},
            cost_monthly=200.0,
        )
        finding = OversizedVMRule().evaluate(snap)
        assert finding is not None
        assert finding.finops_method == "ESTIMATED"
        assert finding.finops_confidence == "MEDIUM"
        assert finding.estimated_impact_monthly_usd == 100.0
        assert finding.waste_monthly_usd == 0.0

    def test_hot_blob_is_estimated_medium(self):
        snap = _snap(
            "Microsoft.Storage/storageAccounts",
            config={"access_tier": "Hot", "days_since_last_access": 45},
            cost_monthly=50.0,
        )
        finding = HotTierBlobNotAccessedRule().evaluate(snap)
        assert finding is not None
        assert finding.finops_method == "ESTIMATED"
        assert finding.finops_confidence == "MEDIUM"
        assert finding.estimated_impact_monthly_usd == 20.0
        assert finding.waste_monthly_usd == 0.0

    def test_devtest_is_estimated_medium(self):
        snap = _snap(
            "Microsoft.Compute/virtualMachines",
            config={"auto_shutdown_enabled": False},
            tags={"environment": "dev"},
            cost_monthly=100.0,
        )
        finding = DevTestOutsideBusinessHoursRule().evaluate(snap)
        assert finding is not None
        assert finding.finops_method == "ESTIMATED"
        assert finding.finops_confidence == "MEDIUM"
        assert finding.estimated_impact_monthly_usd == 65.0
        assert finding.waste_monthly_usd == 0.0

    def test_appgw_is_estimated_medium(self):
        snap = _snap(
            "Microsoft.Network/applicationGateways",
            config={"capacity_utilisation_pct": 4.0},
            cost_monthly=300.0,
        )
        finding = AppGatewayLowUtilisationRule().evaluate(snap)
        assert finding is not None
        assert finding.finops_method == "ESTIMATED"
        assert finding.finops_confidence == "MEDIUM"
        assert finding.estimated_impact_monthly_usd == 210.0
        assert finding.waste_monthly_usd == 0.0

    def test_aks_is_estimated_medium(self):
        snap = _snap(
            "Microsoft.ContainerService/managedClusters",
            config={"autoscaler_enabled": False},
            cost_monthly=400.0,
        )
        finding = AKSNoAutoscalerRule().evaluate(snap)
        assert finding is not None
        assert finding.finops_method == "ESTIMATED"
        assert finding.finops_confidence == "MEDIUM"
        assert finding.estimated_impact_monthly_usd == 120.0
        assert finding.waste_monthly_usd == 0.0

    def test_effective_impact_uses_estimate(self):
        snap = _snap(
            "Microsoft.Compute/virtualMachines",
            config={"avg_cpu_7d": 5.0, "avg_memory_7d": 8.0, "metric_sample_count": 240, "metric_observation_days": 14},
            cost_monthly=200.0,
        )
        finding = OversizedVMRule().evaluate(snap)
        assert finding is not None
        assert finding.effective_monthly_impact_usd == 100.0
