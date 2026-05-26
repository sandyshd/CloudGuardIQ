"""CloudGuardIQ — Storage account security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingCategory, FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class StorageHttpsOnlyRule:
    """Check that storage accounts enforce HTTPS-only traffic."""

    rule_id: str = "STORAGE_HTTPS_ONLY"
    resource_types: list[str] = ["Microsoft.Storage/storageAccounts"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate HTTPS enforcement on storage account."""
        findings: list[FindingResult] = []
        https_only = snapshot.properties.get("supportsHttpsTrafficOnly", True)
        if not https_only:
            name = snapshot.resource_name
            findings.append(
                FindingResult(
                    snapshot_id=snapshot.id,
                    rule_id=self.rule_id,
                    title="Storage account allows HTTP traffic",
                    description=(
                        f"Storage account '{name}' does not enforce HTTPS."
                    ),
                    severity=Severity.HIGH,
                    category=FindingCategory.SECURITY,
                    resource_id=snapshot.resource_id,
                    resource_type=snapshot.resource_type,
                    resource_name=name,
                    evidence={"supportsHttpsTrafficOnly": False},
                    recommended_action="Enable HTTPS-only on the storage account.",
                )
            )
        return findings


class StoragePublicAccessRule:
    """Check that storage accounts disable public blob access."""

    rule_id: str = "STORAGE_PUBLIC_ACCESS"
    resource_types: list[str] = ["Microsoft.Storage/storageAccounts"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate public blob access settings."""
        findings: list[FindingResult] = []
        public_access = snapshot.properties.get("allowBlobPublicAccess", False)
        if public_access:
            name = snapshot.resource_name
            findings.append(
                FindingResult(
                    snapshot_id=snapshot.id,
                    rule_id=self.rule_id,
                    title="Storage account allows public blob access",
                    description=(
                        f"Storage account '{name}' allows public blob access."
                    ),
                    severity=Severity.CRITICAL,
                    category=FindingCategory.SECURITY,
                    resource_id=snapshot.resource_id,
                    resource_type=snapshot.resource_type,
                    resource_name=name,
                    evidence={"allowBlobPublicAccess": True},
                    recommended_action="Disable public blob access.",
                )
            )
        return findings


# ---------------------------------------------------------------------------
# NativeScanner PolicyRule-based storage rules (STOR-001 … STOR-010)
# ---------------------------------------------------------------------------


class PublicBlobAccessRule(PolicyRule):
    """STOR-001: Flag storage accounts with public blob access enabled."""

    rule_id: str = "STOR-001"
    rule_name: str = "Public blob access enabled"
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_3.1",
        "SOC2_CC6.1",
        "NIST_SC-8",
        "ISO_27001_A.8.24",
        "PCI_DSS_4.2.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if ``allow_blob_public_access`` is True."""
        if snapshot.config.get("allow_blob_public_access") is True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Storage account '{snapshot.resource_name}' has "
                    "public blob access enabled."
                ),
                evidence={"allow_blob_public_access": True},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class HttpTrafficAllowedRule(PolicyRule):
    """STOR-002: Flag storage accounts that allow HTTP (non-HTTPS) traffic."""

    rule_id: str = "STOR-002"
    rule_name: str = "HTTP traffic allowed (not HTTPS-only)"
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_3.2",
        "ISO_27001_A.8.24",
        "PCI_DSS_3.5.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if ``enable_https_traffic_only`` is False."""
        if snapshot.config.get("enable_https_traffic_only") is False:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Storage account '{snapshot.resource_name}' allows "
                    "HTTP traffic."
                ),
                evidence={"enable_https_traffic_only": False},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class MinTlsVersionRule(PolicyRule):
    """STOR-003: Flag storage accounts with minimum TLS version below 1.2."""

    rule_id: str = "STOR-003"
    rule_name: str = "Minimum TLS version below 1.2"
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_3.3",
        "PCI_DSS_6.5.4",
        "ISO_27001_A.8.24",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if ``minimum_tls_version`` is TLS1_0 or TLS1_1."""
        tls = snapshot.config.get("minimum_tls_version")
        if tls in ("TLS1_0", "TLS1_1"):
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Storage account '{snapshot.resource_name}' uses "
                    f"{tls} (below TLS 1.2)."
                ),
                evidence={"minimum_tls_version": tls},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class SharedKeyAuthRule(PolicyRule):
    """STOR-004: Flag storage accounts where shared key access is enabled."""

    rule_id: str = "STOR-004"
    rule_name: str = "Shared key authentication enabled"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_3.4",
        "ISO_27001_A.8.24",
        "PCI_DSS_3.7.4",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if ``allow_shared_key_access`` is not False."""
        if snapshot.config.get("allow_shared_key_access") is not False:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Storage account '{snapshot.resource_name}' allows "
                    "shared key authentication."
                ),
                evidence={
                    "allow_shared_key_access": snapshot.config.get(
                        "allow_shared_key_access"
                    ),
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class NetworkDefaultActionRule(PolicyRule):
    """STOR-005: Flag storage accounts where default network action is not Deny."""

    rule_id: str = "STOR-005"
    rule_name: str = "Network default action not Deny"
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_3.5",
        "NIST_SC-7",
        "ISO_27001_A.8.20",
        "PCI_DSS_1.3.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if ``network_default_action`` is not 'Deny'."""
        action = snapshot.config.get("network_default_action")
        if action != "Deny":
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Storage account '{snapshot.resource_name}' network "
                    f"default action is '{action}' instead of 'Deny'."
                ),
                evidence={"network_default_action": action},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class BlobSoftDeleteRule(PolicyRule):
    """STOR-006: Flag storage accounts without blob soft delete."""

    rule_id: str = "STOR-006"
    rule_name: str = "Soft delete not enabled for blobs"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_3.8",
        "ISO_27001_A.8.24",
        "PCI_DSS_3.6.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if ``blob_soft_delete_enabled`` is not True."""
        if snapshot.config.get("blob_soft_delete_enabled") is not True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Storage account '{snapshot.resource_name}' does not "
                    "have blob soft delete enabled."
                ),
                evidence={
                    "blob_soft_delete_enabled": snapshot.config.get(
                        "blob_soft_delete_enabled"
                    ),
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class BlobVersioningRule(PolicyRule):
    """STOR-007: Flag storage accounts without blob versioning."""

    rule_id: str = "STOR-007"
    rule_name: str = "Blob versioning not enabled"
    severity: Severity = Severity.LOW
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_3.9",
        "ISO_27001_A.8.15",
        "PCI_DSS_10.2.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if ``blob_versioning_enabled`` is not True."""
        if snapshot.config.get("blob_versioning_enabled") is not True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Storage account '{snapshot.resource_name}' does not "
                    "have blob versioning enabled."
                ),
                evidence={
                    "blob_versioning_enabled": snapshot.config.get(
                        "blob_versioning_enabled"
                    ),
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class InfrastructureEncryptionRule(PolicyRule):
    """STOR-008: Flag storage accounts without infrastructure encryption."""

    rule_id: str = "STOR-008"
    rule_name: str = "Infrastructure encryption not enabled"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_3.10",
        "ISO_27001_A.8.13",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if ``infrastructure_encryption_enabled`` is not True."""
        if snapshot.config.get("infrastructure_encryption_enabled") is not True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Storage account '{snapshot.resource_name}' does not "
                    "have infrastructure encryption enabled."
                ),
                evidence={
                    "infrastructure_encryption_enabled": snapshot.config.get(
                        "infrastructure_encryption_enabled"
                    ),
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class DiagnosticLoggingRule(PolicyRule):
    """STOR-009: Flag storage accounts without diagnostic logging."""

    rule_id: str = "STOR-009"
    rule_name: str = "No diagnostic logging configured"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "SOC2_CC7.2",
        "NIST_AU-2",
        "ISO_27001_A.8.15",
        "PCI_DSS_10.2.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if ``diagnostic_logging_enabled`` is not True."""
        if snapshot.config.get("diagnostic_logging_enabled") is not True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Storage account '{snapshot.resource_name}' has no "
                    "diagnostic logging configured."
                ),
                evidence={
                    "diagnostic_logging_enabled": snapshot.config.get(
                        "diagnostic_logging_enabled"
                    ),
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class LifecycleManagementRule(PolicyRule):
    """STOR-010: Flag costly storage accounts without lifecycle management (FinOps)."""

    rule_id: str = "STOR-010"
    rule_name: str = "No lifecycle management policy"
    severity: Severity = Severity.LOW
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = []

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when lifecycle policy is missing and cost > $50/mo."""
        if (
            snapshot.config.get("lifecycle_policy_exists") is not True
            and snapshot.cost_monthly > 50
        ):
            waste = round(snapshot.cost_monthly * 0.35, 2)
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Storage account '{snapshot.resource_name}' costs "
                    f"${snapshot.cost_monthly:.2f}/mo with no lifecycle policy. "
                    f"Estimated waste: ${waste:.2f}/mo."
                ),
                evidence={
                    "lifecycle_policy_exists": False,
                    "cost_monthly": snapshot.cost_monthly,
                },
                waste_monthly_usd=waste,
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None
