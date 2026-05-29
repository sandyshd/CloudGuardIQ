"""CloudGuardIQ — AWS Secrets Manager + ACM rules."""

from __future__ import annotations

from datetime import datetime, timezone

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class SecretRotationDisabledRule(PolicyRule):
    """AWS-SM-001: Flag Secrets Manager secrets without rotation enabled."""

    rule_id: str = "AWS-SM-001"
    rule_name: str = "Secret rotation disabled"
    resource_types: list[str] = ["AWS::SecretsManager::Secret"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_3.0_3.10",
        "NIST_IA-5",
        "PCI_DSS_3.6.4",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``rotation_enabled`` is False."""
        if snapshot.config.get("rotation_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Secret '{snapshot.resource_name}' does not have automatic "
                "rotation enabled."
            ),
            evidence={
                "rotation_enabled": snapshot.config.get(
                    "rotation_enabled", False
                ),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class AcmCertificateExpiringRule(PolicyRule):
    """AWS-ACM-001: Flag ACM certificates expiring within 30 days."""

    rule_id: str = "AWS-ACM-001"
    rule_name: str = "ACM certificate expiring soon"
    resource_types: list[str] = ["AWS::CertificateManager::Certificate"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = ["NIST_SC-17", "PCI_DSS_4.1"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``days_to_expiry`` <= 30."""
        days = snapshot.config.get("days_to_expiry")
        if days is None or int(days) > 30:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"ACM certificate '{snapshot.resource_name}' expires in "
                f"{days} day(s)."
            ),
            evidence={
                "days_to_expiry": days,
                "evaluated_at": datetime.now(timezone.utc).isoformat(),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )
