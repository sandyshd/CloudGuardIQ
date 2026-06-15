"""CloudGuardIQ — Key Vault security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingCategory, FindingType, Severity
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


# ---------------------------------------------------------------------------
# NativeScanner PolicyRule-based Key Vault rules (KV-001 ... KV-005)
# ---------------------------------------------------------------------------


class SoftDeleteRule(PolicyRule):
    """KV-001: Soft delete not enabled."""

    rule_id: str = "KV-001"
    resource_types: list[str] = ["Microsoft.KeyVault/vaults"]
    rule_name: str = "Soft delete not enabled"
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_8.1",
        "ISO_27001_A.8.13",
        "PCI_DSS_3.6.1",
        "HIPAA_164.308(a)(7)(ii)(A)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if soft delete is not enabled."""
        if snapshot.config.get("soft_delete_enabled") is not True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Key Vault '{snapshot.resource_name}' does not have "
                    "soft delete enabled."
                ),
                evidence={
                    "soft_delete_enabled": snapshot.config.get(
                        "soft_delete_enabled"
                    ),
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class PurgeProtectionRule(PolicyRule):
    """KV-002: Purge protection not enabled."""

    rule_id: str = "KV-002"
    resource_types: list[str] = ["Microsoft.KeyVault/vaults"]
    rule_name: str = "Purge protection not enabled"
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_8.2",
        "ISO_27001_A.8.13",
        "PCI_DSS_3.6.1",
        "HIPAA_164.308(a)(7)(ii)(A)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if purge protection is not enabled."""
        if snapshot.config.get("purge_protection_enabled") is not True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Key Vault '{snapshot.resource_name}' does not have "
                    "purge protection enabled."
                ),
                evidence={
                    "purge_protection_enabled": snapshot.config.get(
                        "purge_protection_enabled"
                    ),
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class PublicNetworkAccessRule(PolicyRule):
    """KV-003: Public network access enabled (not private endpoint only)."""

    rule_id: str = "KV-003"
    resource_types: list[str] = ["Microsoft.KeyVault/vaults"]
    rule_name: str = "Public network access enabled"
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_8.5",
        "NIST_SC-7",
        "ISO_27001_A.8.22",
        "PCI_DSS_1.3.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if public network access is enabled."""
        if snapshot.config.get("public_network_access_enabled") is True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Key Vault '{snapshot.resource_name}' has public network "
                    "access enabled instead of private endpoint only."
                ),
                evidence={"public_network_access_enabled": True},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class NoDiagnosticLoggingRule(PolicyRule):
    """KV-004: No diagnostic logging configured."""

    rule_id: str = "KV-004"
    resource_types: list[str] = ["Microsoft.KeyVault/vaults"]
    rule_name: str = "No diagnostic logging configured"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_8.6",
        "SOC2_CC7.2",
        "ISO_27001_A.8.15",
        "PCI_DSS_10.2.1",
        "HIPAA_164.312(b)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if diagnostic logging is not configured."""
        if snapshot.config.get("diagnostic_logging_enabled") is not True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Key Vault '{snapshot.resource_name}' has no diagnostic "
                    "logging configured."
                ),
                evidence={
                    "diagnostic_logging_enabled": snapshot.config.get(
                        "diagnostic_logging_enabled"
                    ),
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class SecretNoExpiryRule(PolicyRule):
    """KV-005: Secrets with no expiry date set."""

    rule_id: str = "KV-005"
    resource_types: list[str] = ["Microsoft.KeyVault/vaults"]
    rule_name: str = "Secrets with no expiry date set"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_8.3",
        "ISO_27001_A.8.24",
        "PCI_DSS_3.7.4",
        "HIPAA_164.312(a)(2)(iv)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if secrets have no expiry date."""
        if snapshot.config.get("secrets_without_expiry", 0) > 0:
            count = snapshot.config["secrets_without_expiry"]
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Key Vault '{snapshot.resource_name}' has {count} "
                    "secret(s) with no expiry date set."
                ),
                evidence={"secrets_without_expiry": count},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None
