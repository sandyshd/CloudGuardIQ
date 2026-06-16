"""CloudGuardIQ — FinOps cost optimization rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.billing.pricing import get_pricing_service
from cloudguardiq.core.enums import FindingCategory, FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class UnderutilizedVMRule:
    """Detect VMs with very low CPU utilization suggesting waste."""

    rule_id: str = "FINOPS_UNDERUTILIZED_VM"
    resource_types: list[str] = ["Microsoft.Compute/virtualMachines"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate VM CPU utilization metrics for cost waste."""
        findings: list[FindingResult] = []
        avg_cpu = snapshot.properties.get("avgCpuPercent")
        if avg_cpu is not None and avg_cpu < 5.0 and snapshot.cost_monthly > 0:
            findings.append(
                FindingResult(
                    snapshot_id=snapshot.id,
                    rule_id=self.rule_id,
                    title="Underutilized VM detected",
                    description=(
                        f"VM '{snapshot.resource_name}' has avg CPU {avg_cpu:.1f}% "
                        f"and costs ${snapshot.cost_monthly:.2f}/mo."
                    ),
                    severity=Severity.MEDIUM,
                    category=FindingCategory.COST,
                    resource_id=snapshot.resource_id,
                    resource_type=snapshot.resource_type,
                    resource_name=snapshot.resource_name,
                    evidence={"avgCpuPercent": avg_cpu, "costMonthly": snapshot.cost_monthly},
                    recommended_action="Consider resizing or deallocating the VM.",
                )
            )
        return findings


class UnattachedDiskRule:
    """Detect unattached managed disks incurring cost."""

    rule_id: str = "FINOPS_UNATTACHED_DISK"
    resource_types: list[str] = ["Microsoft.Compute/disks"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate disk attachment status."""
        findings: list[FindingResult] = []
        disk_state = snapshot.properties.get("diskState", "")
        if disk_state == "Unattached" and snapshot.cost_monthly > 0:
            findings.append(
                FindingResult(
                    snapshot_id=snapshot.id,
                    rule_id=self.rule_id,
                    title="Unattached managed disk",
                    description=(
                        f"Disk '{snapshot.resource_name}' is unattached "
                        f"and costs ${snapshot.cost_monthly:.2f}/mo."
                    ),
                    severity=Severity.LOW,
                    category=FindingCategory.COST,
                    resource_id=snapshot.resource_id,
                    resource_type=snapshot.resource_type,
                    resource_name=snapshot.resource_name,
                    evidence={"diskState": disk_state, "costMonthly": snapshot.cost_monthly},
                    recommended_action="Delete or snapshot the unattached disk.",
                )
            )
        return findings


# ---------------------------------------------------------------------------
# NativeScanner PolicyRule-based FinOps rules (FIN-001 ... FIN-008)
# ---------------------------------------------------------------------------


class UnattachedManagedDiskRule(PolicyRule):
    """FIN-001: Unattached managed disk (no VM assigned)."""

    rule_id: str = "FIN-001"
    resource_types: list[str] = ["Microsoft.Compute/disks"]
    rule_name: str = "Unattached managed disk"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = []

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if disk is unattached and costing money."""
        if snapshot.config.get("disk_state") == "Unattached" and snapshot.cost_monthly > 0:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Managed disk '{snapshot.resource_name}' is unattached "
                    f"and costs ${snapshot.cost_monthly:.2f}/mo."
                ),
                evidence={
                    "disk_state": "Unattached",
                    "cost_monthly": snapshot.cost_monthly,
                },
                waste_monthly_usd=snapshot.cost_monthly,
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class UnassignedPublicIPRule(PolicyRule):
    """FIN-002: Unassigned public IP address."""

    rule_id: str = "FIN-002"
    resource_types: list[str] = ["Microsoft.Network/publicIPAddresses"]
    rule_name: str = "Unassigned public IP address"
    severity: Severity = Severity.LOW
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = []

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if public IP is not associated with any resource.

        Waste estimate is sourced from the Azure Retail Prices cache for
        the resource's region. If the cache is cold or the SKU is not
        present we fall back to the bundled US-East list price so this
        rule never reports ``$0`` waste for a real unassigned IP.
        """
        assoc = snapshot.config.get("ip_association")
        if assoc is None or assoc == "":
            price = get_pricing_service().get_price(
                "public_ip_standard",
                snapshot.region,
                default=3.65,
            )
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Public IP '{snapshot.resource_name}' is reserved but "
                    "not attached to any resource."
                ),
                evidence={
                    "ip_association": None,
                    "price_source": "azure_retail_prices",
                    "region": snapshot.region,
                },
                waste_monthly_usd=round(float(price), 2),
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class EmptyLoadBalancerRule(PolicyRule):
    """FIN-003: Empty load balancer (no backend pool configured)."""

    rule_id: str = "FIN-003"
    resource_types: list[str] = ["Microsoft.Network/loadBalancers"]
    rule_name: str = "Empty load balancer"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = []

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if LB has no backend pool members."""
        backend_count = snapshot.config.get("backend_pool_count", 0)
        if backend_count == 0 and snapshot.cost_monthly > 0:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Load balancer '{snapshot.resource_name}' has no backend "
                    f"pool configured and costs ${snapshot.cost_monthly:.2f}/mo."
                ),
                evidence={
                    "backend_pool_count": 0,
                    "cost_monthly": snapshot.cost_monthly,
                },
                waste_monthly_usd=snapshot.cost_monthly,
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class HotTierBlobNotAccessedRule(PolicyRule):
    """FIN-004: Hot-tier storage blobs not accessed in 30+ days."""

    rule_id: str = "FIN-004"
    resource_types: list[str] = ["Microsoft.Storage/storageAccounts"]
    rule_name: str = "Hot-tier blobs not accessed in 30+ days"
    severity: Severity = Severity.LOW
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = []

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if blobs in hot tier were not accessed in 30+ days."""
        days = snapshot.config.get("days_since_last_access")
        tier = snapshot.config.get("access_tier", "").lower()
        if tier == "hot" and days is not None and days >= 30 and snapshot.cost_monthly > 0:
            waste = round(snapshot.cost_monthly * 0.40, 2)
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Storage account '{snapshot.resource_name}' has hot-tier "
                    f"blobs not accessed in {days} days. Move to Cool tier to "
                    f"save ~${waste:.2f}/mo."
                ),
                evidence={
                    "days_since_last_access": days,
                    "access_tier": "Hot",
                    "cost_monthly": snapshot.cost_monthly,
                },
                estimated_impact_monthly_usd=waste,
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class OversizedVMRule(PolicyRule):
    """FIN-005: Oversized VM SKU — utilisation <20% CPU and <20% memory."""

    rule_id: str = "FIN-005"
    resource_types: list[str] = ["Microsoft.Compute/virtualMachines"]
    rule_name: str = "Oversized VM SKU"
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = []

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if VM CPU and memory are both <20% for 7 days."""
        avg_cpu = snapshot.config.get("avg_cpu_7d", 100)
        avg_mem = snapshot.config.get("avg_memory_7d", 100)
        if avg_cpu < 20 and avg_mem < 20 and snapshot.cost_monthly > 0:
            waste = round(snapshot.cost_monthly * 0.50, 2)
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"VM '{snapshot.resource_name}' is oversized with avg CPU "
                    f"{avg_cpu:.1f}% and memory {avg_mem:.1f}% over 7 days. "
                    f"Estimated waste: ${waste:.2f}/mo."
                ),
                evidence={
                    "avg_cpu_7d": avg_cpu,
                    "avg_memory_7d": avg_mem,
                    "cost_monthly": snapshot.cost_monthly,
                },
                estimated_impact_monthly_usd=waste,
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class DevTestOutsideBusinessHoursRule(PolicyRule):
    """FIN-006: Dev/test resources running outside business hours."""

    rule_id: str = "FIN-006"
    resource_types: list[str] = ["Microsoft.Compute/virtualMachines"]
    rule_name: str = "Dev/test resource running outside business hours"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = []

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if dev/test resource runs 24/7."""
        env_tag = snapshot.tags.get("environment", "").lower()
        auto_shutdown = snapshot.config.get("auto_shutdown_enabled", False)
        if env_tag in ("dev", "test") and not auto_shutdown and snapshot.cost_monthly > 0:
            waste = round(snapshot.cost_monthly * 0.65, 2)
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Dev/test resource '{snapshot.resource_name}' runs "
                    "outside business hours with no auto-shutdown. "
                    f"Estimated waste: ${waste:.2f}/mo."
                ),
                evidence={
                    "environment_tag": env_tag,
                    "auto_shutdown_enabled": False,
                    "cost_monthly": snapshot.cost_monthly,
                },
                estimated_impact_monthly_usd=waste,
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class AppGatewayLowUtilisationRule(PolicyRule):
    """FIN-007: Application Gateway with <10% capacity utilisation."""

    rule_id: str = "FIN-007"
    resource_types: list[str] = ["Microsoft.Network/applicationGateways"]
    rule_name: str = "Application Gateway low utilisation"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = []

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if App Gateway capacity utilisation <10%."""
        util = snapshot.config.get("capacity_utilisation_pct", 100)
        if util < 10 and snapshot.cost_monthly > 0:
            waste = round(snapshot.cost_monthly * 0.70, 2)
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Application Gateway '{snapshot.resource_name}' has only "
                    f"{util:.1f}% capacity utilisation. "
                    f"Estimated waste: ${waste:.2f}/mo."
                ),
                evidence={
                    "capacity_utilisation_pct": util,
                    "cost_monthly": snapshot.cost_monthly,
                },
                estimated_impact_monthly_usd=waste,
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class AKSNoAutoscalerRule(PolicyRule):
    """FIN-008: AKS node pool always at max (no autoscaler configured)."""

    rule_id: str = "FIN-008"
    resource_types: list[str] = ["Microsoft.ContainerService/managedClusters"]
    rule_name: str = "AKS node pool without autoscaler"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = []

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if AKS node pool has no autoscaler configured."""
        if snapshot.config.get("autoscaler_enabled") is not True and snapshot.cost_monthly > 0:
            waste = round(snapshot.cost_monthly * 0.30, 2)
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"AKS node pool '{snapshot.resource_name}' has no "
                    f"autoscaler configured. Estimated waste: ${waste:.2f}/mo."
                ),
                evidence={
                    "autoscaler_enabled": snapshot.config.get("autoscaler_enabled"),
                    "cost_monthly": snapshot.cost_monthly,
                },
                estimated_impact_monthly_usd=waste,
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None
