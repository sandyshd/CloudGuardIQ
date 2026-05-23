"""CloudGuardIQ -- GCP Compute Engine security + FinOps rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class InstancePublicIpRule(PolicyRule):
    """GCP-CE-001: Flag Compute Engine VMs with a public external IP."""

    rule_id: str = "GCP-CE-001"
    rule_name: str = "Compute Engine instance has external IP"
    resource_types: list[str] = ["google.compute.Instance"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["CIS_GCP_4.9", "NIST_SC-7"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when the VM has at least one external IP."""
        external_ips = snapshot.config.get("external_ips") or []
        if not external_ips:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Compute Engine instance '{snapshot.resource_name}' is "
                f"reachable on external IP(s) {', '.join(external_ips)}."
            ),
            evidence={"external_ips": list(external_ips)},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class DiskCmekEncryptionRule(PolicyRule):
    """GCP-CE-002: Flag persistent disks that lack a customer-managed
    encryption key (CMEK).

    GCP encrypts all persistent disks at rest by default with Google-managed
    keys, but CIS and most enterprise security baselines require CMEK so the
    customer retains key control.
    """

    rule_id: str = "GCP-CE-002"
    rule_name: str = "Persistent disk not CMEK-encrypted"
    resource_types: list[str] = ["google.compute.Disk"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_4.7",
        "NIST_SC-28",
        "SOC2_CC6.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``cmek_encrypted`` is not True."""
        if snapshot.config.get("cmek_encrypted") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Persistent disk '{snapshot.resource_name}' is encrypted "
                "with a Google-managed key. CIS baselines require CMEK."
            ),
            evidence={"cmek_encrypted": snapshot.config.get("cmek_encrypted", False)},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class UnattachedDiskRule(PolicyRule):
    """GCP-CE-003: Flag persistent disks with no attached users (waste)."""

    rule_id: str = "GCP-CE-003"
    rule_name: str = "Persistent disk is unattached"
    resource_types: list[str] = ["google.compute.Disk"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = ["FINOPS_BP_1.1"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when the disk has no users (unattached)."""
        users = snapshot.config.get("users") or []
        if users:
            return None
        size_gb = snapshot.config.get("size_gb") or 0
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Persistent disk '{snapshot.resource_name}' ({size_gb} GiB) "
                "is unattached and continues to incur storage charges."
            ),
            evidence={"users": [], "size_gb": size_gb},
            waste_monthly_usd=float(snapshot.cost_monthly),
            compliance_frameworks=list(self.compliance_frameworks),
        )
