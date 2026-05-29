"""CloudGuardIQ -- GCP Cloud SQL security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class CloudSqlPublicIpRule(PolicyRule):
    """GCP-SQL-001: Flag Cloud SQL instances with a public IPv4 address."""

    rule_id: str = "GCP-SQL-001"
    rule_name: str = "Cloud SQL instance has public IP"
    resource_types: list[str] = ["google.sql.Instance"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_6.6",
        "NIST_SC-7",
        "PCI_DSS_1.3.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``ipv4_enabled`` is True."""
        if snapshot.config.get("ipv4_enabled") is not True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Cloud SQL instance '{snapshot.resource_name}' has a public "
                "IPv4 address. Use Private IP or Cloud SQL Auth Proxy."
            ),
            evidence={"ipv4_enabled": True},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class CloudSqlBackupDisabledRule(PolicyRule):
    """GCP-SQL-002: Flag Cloud SQL instances with automated backups disabled."""

    rule_id: str = "GCP-SQL-002"
    rule_name: str = "Cloud SQL automated backups disabled"
    resource_types: list[str] = ["google.sql.Instance"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_GCP_6.7",
        "NIST_CP-9",
        "ISO_27001_A.8.13",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``backup_enabled`` is not True."""
        if snapshot.config.get("backup_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Cloud SQL instance '{snapshot.resource_name}' does not "
                "have automated backups enabled."
            ),
            evidence={
                "backup_enabled": snapshot.config.get("backup_enabled", False),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class CloudSqlRequireSslRule(PolicyRule):
    """GCP-SQL-003: Flag Cloud SQL instances not requiring SSL connections."""

    rule_id: str = "GCP-SQL-003"
    rule_name: str = "Cloud SQL does not require SSL"
    resource_types: list[str] = ["google.sql.Instance"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_6.4",
        "NIST_SC-8",
        "PCI_DSS_4.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``require_ssl`` is not True."""
        if snapshot.config.get("require_ssl") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Cloud SQL instance '{snapshot.resource_name}' accepts "
                "unencrypted connections (require_ssl=False)."
            ),
            evidence={
                "require_ssl": snapshot.config.get("require_ssl", False),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )
