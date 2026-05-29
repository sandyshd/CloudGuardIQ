"""CloudGuardIQ — Compute security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingCategory, FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class VMUnmanagedDisksRule:
    """Check for VMs using unmanaged disks."""

    rule_id: str = "COMPUTE_UNMANAGED_DISKS"
    resource_types: list[str] = ["Microsoft.Compute/virtualMachines"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate VM for unmanaged disk usage."""
        findings: list[FindingResult] = []
        storage_profile = snapshot.properties.get("storageProfile", {})
        os_disk = storage_profile.get("osDisk", {})
        if os_disk.get("vhd"):
            name = snapshot.resource_name
            findings.append(
                FindingResult(
                    snapshot_id=snapshot.id,
                    rule_id=self.rule_id,
                    title="VM uses unmanaged disks",
                    description=(
                        f"VM '{name}' uses unmanaged (VHD) disks."
                    ),
                    severity=Severity.MEDIUM,
                    category=FindingCategory.SECURITY,
                    resource_id=snapshot.resource_id,
                    resource_type=snapshot.resource_type,
                    resource_name=name,
                    evidence={"osDisk_vhd": os_disk["vhd"]},
                    recommended_action=(
                        "Migrate to managed disks for better "
                        "security and reliability."
                    ),
                )
            )
        return findings


class VMNoEncryptionRule:
    """Check for VMs without disk encryption."""

    rule_id: str = "COMPUTE_NO_ENCRYPTION"
    resource_types: list[str] = ["Microsoft.Compute/virtualMachines"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate VM for disk encryption status."""
        findings: list[FindingResult] = []
        encryption = snapshot.properties.get("encryptionAtHost", False)
        if not encryption:
            name = snapshot.resource_name
            findings.append(
                FindingResult(
                    snapshot_id=snapshot.id,
                    rule_id=self.rule_id,
                    title="VM disk encryption not enabled",
                    description=(
                        f"VM '{name}' does not have "
                        "encryption at host enabled."
                    ),
                    severity=Severity.HIGH,
                    category=FindingCategory.SECURITY,
                    resource_id=snapshot.resource_id,
                    resource_type=snapshot.resource_type,
                    resource_name=name,
                    evidence={"encryptionAtHost": False},
                    recommended_action="Enable encryption at host.",
                )
            )
        return findings


# ---------------------------------------------------------------------------
# NativeScanner PolicyRule-based Compute rules (VM-001 ... VM-007)
# ---------------------------------------------------------------------------


class OSDiskEncryptionRule(PolicyRule):
    """VM-001: OS disk encryption not enabled."""

    rule_id: str = "VM-001"
    rule_name: str = "OS disk encryption not enabled"
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_7.2",
        "NIST_SC-28",
        "ISO_27001_A.8.24",
        "PCI_DSS_3.5.1",
        "HIPAA_164.312(a)(2)(iv)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if OS disk encryption is disabled."""
        if snapshot.config.get("os_disk_encryption_enabled") is not True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"VM '{snapshot.resource_name}' does not have OS disk "
                    "encryption enabled."
                ),
                evidence={
                    "os_disk_encryption_enabled": snapshot.config.get(
                        "os_disk_encryption_enabled"
                    ),
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class UnmanagedDiskRule(PolicyRule):
    """VM-002: Unmanaged disk in use (old classic disk)."""

    rule_id: str = "VM-002"
    rule_name: str = "Unmanaged disk in use"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_7.1",
        "ISO_27001_A.8.9",
        "PCI_DSS_2.2.1",
        "HIPAA_164.312(c)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if unmanaged (VHD) disks are in use."""
        if snapshot.config.get("uses_unmanaged_disk") is True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"VM '{snapshot.resource_name}' uses unmanaged (classic) "
                    "disks."
                ),
                evidence={"uses_unmanaged_disk": True},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class NoBackupPolicyRule(PolicyRule):
    """VM-003: No backup policy assigned."""

    rule_id: str = "VM-003"
    rule_name: str = "No backup policy assigned"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_7.4",
        "ISO_27001_A.8.13",
        "PCI_DSS_12.10.1",
        "HIPAA_164.308(a)(7)(ii)(A)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if no backup policy is configured."""
        if snapshot.config.get("backup_policy_enabled") is not True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"VM '{snapshot.resource_name}' has no backup policy "
                    "assigned."
                ),
                evidence={
                    "backup_policy_enabled": snapshot.config.get(
                        "backup_policy_enabled"
                    ),
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class PublicIPDirectAttachedRule(PolicyRule):
    """VM-004: Public IP directly attached to VM NIC (not via load balancer)."""

    rule_id: str = "VM-004"
    rule_name: str = "Public IP directly attached to VM"
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_7.3",
        "ISO_27001_A.8.20",
        "PCI_DSS_1.3.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if a public IP is directly attached to the VM NIC."""
        if snapshot.config.get("public_ip_directly_attached") is True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"VM '{snapshot.resource_name}' has a public IP directly "
                    "attached to its NIC instead of via a load balancer."
                ),
                evidence={"public_ip_directly_attached": True},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class OutdatedOSImageRule(PolicyRule):
    """VM-005: Outdated OS image (Windows 2016 or Ubuntu 18.04 or older)."""

    rule_id: str = "VM-005"
    rule_name: str = "Outdated OS image"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "NIST_SI-2",
        "ISO_27001_A.8.8",
        "PCI_DSS_6.3.3",
        "HIPAA_164.308(a)(5)(ii)(B)",
    ]

    _outdated_patterns: tuple[str, ...] = (
        "windows2016",
        "windowsserver2016",
        "windows2012",
        "windowsserver2012",
        "ubuntu1804",
        "ubuntu1604",
        "ubuntu1404",
    )

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if the VM runs an outdated OS image."""
        raw = snapshot.config.get("os_image", "")
        os_image = raw.lower().replace(" ", "").replace("-", "")
        os_image = os_image.replace("_", "").replace(".", "")
        for pattern in self._outdated_patterns:
            if pattern in os_image:
                return FindingResult(
                    resource_snapshot=snapshot,
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    finding_type=self.finding_type,
                    description=(
                        f"VM '{snapshot.resource_name}' runs outdated OS image "
                        f"'{snapshot.config.get('os_image')}'."
                    ),
                    evidence={"os_image": snapshot.config.get("os_image")},
                    compliance_frameworks=list(self.compliance_frameworks),
                )
        return None


class MissingCostTagsRule(PolicyRule):
    """VM-006: VM missing required cost attribution tags."""

    rule_id: str = "VM-006"
    rule_name: str = "Missing required cost attribution tags"
    severity: Severity = Severity.LOW
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = []

    _required_tags: tuple[str, ...] = ("environment", "owner", "cost-center")

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if required cost attribution tags are missing."""
        tag_keys = {k.lower() for k in snapshot.tags}
        missing = [t for t in self._required_tags if t not in tag_keys]
        if missing:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"VM '{snapshot.resource_name}' is missing required cost "
                    f"attribution tags: {', '.join(missing)}."
                ),
                evidence={"missing_tags": missing},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class IdleVMRule(PolicyRule):
    """VM-007: Idle VM — CPU utilisation <5% over last 7 days."""

    rule_id: str = "VM-007"
    rule_name: str = "Idle VM detected"
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = []

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if VM CPU is <5% over 7 days."""
        avg_cpu = snapshot.config.get("avg_cpu_7d", 100)
        if avg_cpu < 5 and snapshot.cost_monthly > 0:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"VM '{snapshot.resource_name}' is idle with avg CPU "
                    f"{avg_cpu:.1f}% over 7 days, costing "
                    f"${snapshot.cost_monthly:.2f}/mo."
                ),
                evidence={
                    "avg_cpu_7d": avg_cpu,
                    "cost_monthly": snapshot.cost_monthly,
                },
                waste_monthly_usd=snapshot.cost_monthly,
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None
