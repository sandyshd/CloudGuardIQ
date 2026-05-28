"""CloudGuardIQ — AWS RDS security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class RdsStorageEncryptionRule(PolicyRule):
    """AWS-RDS-001: Flag RDS DB instances without storage encryption."""

    rule_id: str = "AWS-RDS-001"
    rule_name: str = "RDS instance storage not encrypted"
    resource_types: list[str] = ["AWS::RDS::DBInstance"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_2.3.1",
        "NIST_SC-28",
        "PCI_DSS_3.5.1",
        "HIPAA_164.312(a)(2)(iv)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``storage_encrypted`` is not True."""
        if snapshot.config.get("storage_encrypted") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"RDS instance '{snapshot.resource_name}' has storage "
                "encryption disabled."
            ),
            evidence={
                "storage_encrypted": snapshot.config.get("storage_encrypted", False),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class RdsPubliclyAccessibleRule(PolicyRule):
    """AWS-RDS-002: Flag RDS DB instances reachable from the internet."""

    rule_id: str = "AWS-RDS-002"
    rule_name: str = "RDS instance publicly accessible"
    resource_types: list[str] = ["AWS::RDS::DBInstance"]
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_2.3.3",
        "NIST_SC-7",
        "PCI_DSS_1.3.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``publicly_accessible`` is True."""
        if snapshot.config.get("publicly_accessible") is not True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"RDS instance '{snapshot.resource_name}' is publicly "
                "accessible from the internet."
            ),
            evidence={"publicly_accessible": True},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class RdsBackupRetentionRule(PolicyRule):
    """AWS-RDS-003: Flag RDS DB instances with backup retention < 7 days."""

    rule_id: str = "AWS-RDS-003"
    rule_name: str = "RDS backup retention too short"
    resource_types: list[str] = ["AWS::RDS::DBInstance"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_AWS_2.3.2",
        "NIST_CP-9",
        "ISO_27001_A.8.13",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``backup_retention_period`` < 7."""
        retention = int(snapshot.config.get("backup_retention_period", 0) or 0)
        if retention >= 7:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"RDS instance '{snapshot.resource_name}' has a backup "
                f"retention period of {retention} days (minimum 7 recommended)."
            ),
            evidence={"backup_retention_period": retention},
            compliance_frameworks=list(self.compliance_frameworks),
        )
