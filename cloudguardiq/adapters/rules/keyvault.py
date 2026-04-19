"""CloudGuardIQ — Key Vault security rules."""

from __future__ import annotations

from cloudguardiq.core.enums import FindingCategory, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class KeyVaultSoftDeleteRule:
    """Check that Key Vault has soft delete enabled."""

    rule_id: str = "KEYVAULT_SOFT_DELETE"
    resource_types: list[str] = ["Microsoft.KeyVault/vaults"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate Key Vault soft delete configuration."""
        findings: list[FindingResult] = []
        soft_delete = snapshot.properties.get("enableSoftDelete", True)
        if not soft_delete:
            name = snapshot.resource_name
            findings.append(
                FindingResult(
                    snapshot_id=snapshot.id,
                    rule_id=self.rule_id,
                    title="Key Vault soft delete disabled",
                    description=(
                        f"Key Vault '{name}' does not have "
                        "soft delete enabled."
                    ),
                    severity=Severity.HIGH,
                    category=FindingCategory.SECURITY,
                    resource_id=snapshot.resource_id,
                    resource_type=snapshot.resource_type,
                    resource_name=name,
                    evidence={"enableSoftDelete": False},
                    recommended_action="Enable soft delete on the Key Vault.",
                )
            )
        return findings


class KeyVaultPurgeProtectionRule:
    """Check that Key Vault has purge protection enabled."""

    rule_id: str = "KEYVAULT_PURGE_PROTECTION"
    resource_types: list[str] = ["Microsoft.KeyVault/vaults"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate Key Vault purge protection configuration."""
        findings: list[FindingResult] = []
        purge_protection = snapshot.properties.get("enablePurgeProtection", False)
        if not purge_protection:
            name = snapshot.resource_name
            findings.append(
                FindingResult(
                    snapshot_id=snapshot.id,
                    rule_id=self.rule_id,
                    title="Key Vault purge protection disabled",
                    description=(
                        f"Key Vault '{name}' lacks purge protection."
                    ),
                    severity=Severity.MEDIUM,
                    category=FindingCategory.SECURITY,
                    resource_id=snapshot.resource_id,
                    resource_type=snapshot.resource_type,
                    resource_name=name,
                    evidence={"enablePurgeProtection": False},
                    recommended_action="Enable purge protection.",
                )
            )
        return findings
