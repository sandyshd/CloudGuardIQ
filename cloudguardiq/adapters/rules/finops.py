"""CloudGuardIQ — FinOps cost optimization rules."""

from __future__ import annotations

from cloudguardiq.core.enums import FindingCategory, Severity
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
