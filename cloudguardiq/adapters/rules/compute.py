"""CloudGuardIQ — Compute security rules."""

from __future__ import annotations

from cloudguardiq.core.enums import FindingCategory, Severity
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
