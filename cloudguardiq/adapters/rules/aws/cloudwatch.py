"""CloudGuardIQ — AWS CloudWatch Logs rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class LogGroupRetentionRule(PolicyRule):
    """AWS-CWL-001: Flag log groups with retention below 365 days (and not 0=forever)."""

    rule_id: str = "AWS-CWL-001"
    rule_name: str = "CloudWatch log group retention below 365 days"
    resource_types: list[str] = ["AWS::Logs::LogGroup"]
    severity: Severity = Severity.LOW
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = ["NIST_AU-11", "ISO_27001_A.8.15"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``retention_in_days`` < 365 (non-zero)."""
        retention = snapshot.config.get("retention_in_days")
        if retention is None or int(retention) >= 365:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Log group '{snapshot.resource_name}' retains entries for "
                f"{retention} days (minimum recommended: 365)."
            ),
            evidence={"retention_in_days": retention},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class LogGroupKmsKeyRule(PolicyRule):
    """AWS-CWL-002: Flag CloudWatch log groups without a CMK."""

    rule_id: str = "AWS-CWL-002"
    rule_name: str = "CloudWatch log group not encrypted with CMK"
    resource_types: list[str] = ["AWS::Logs::LogGroup"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SC-28", "ISO_27001_A.8.24"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``kms_key_id`` is not set."""
        if snapshot.config.get("kms_key_id"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Log group '{snapshot.resource_name}' is encrypted with "
                "the default AWS-managed key."
            ),
            evidence={"kms_key_id": None},
            compliance_frameworks=list(self.compliance_frameworks),
        )
