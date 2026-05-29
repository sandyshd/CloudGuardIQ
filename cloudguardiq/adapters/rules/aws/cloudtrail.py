"""CloudGuardIQ — AWS CloudTrail rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class CloudTrailMultiRegionRule(PolicyRule):
    """AWS-CT-001: Flag CloudTrail trails that are not multi-region."""

    rule_id: str = "AWS-CT-001"
    rule_name: str = "CloudTrail trail is not multi-region"
    resource_types: list[str] = ["AWS::CloudTrail::Trail"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_AWS_3.1",
        "NIST_AU-2",
        "PCI_DSS_10.2",
        "SOC2_CC7.2",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``is_multi_region_trail`` is False."""
        if snapshot.config.get("is_multi_region_trail") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"CloudTrail '{snapshot.resource_name}' is single-region. "
                "Enable multi-region logging to capture all API activity."
            ),
            evidence={"is_multi_region_trail": False},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class CloudTrailNotLoggingRule(PolicyRule):
    """AWS-CT-002: Flag CloudTrail trails that are currently disabled."""

    rule_id: str = "AWS-CT-002"
    rule_name: str = "CloudTrail trail is not logging"
    resource_types: list[str] = ["AWS::CloudTrail::Trail"]
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_AWS_3.1",
        "NIST_AU-2",
        "PCI_DSS_10.2",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``is_logging`` is False."""
        if snapshot.config.get("is_logging") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"CloudTrail '{snapshot.resource_name}' is not currently "
                "logging API events."
            ),
            evidence={"is_logging": snapshot.config.get("is_logging", False)},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class CloudTrailLogFileValidationRule(PolicyRule):
    """AWS-CT-003: Flag CloudTrail trails without log file validation."""

    rule_id: str = "AWS-CT-003"
    rule_name: str = "CloudTrail log file validation disabled"
    resource_types: list[str] = ["AWS::CloudTrail::Trail"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_AWS_3.2",
        "NIST_AU-9",
        "ISO_27001_A.8.15",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``log_file_validation_enabled`` is False."""
        if snapshot.config.get("log_file_validation_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"CloudTrail '{snapshot.resource_name}' has log file "
                "validation disabled — tampering may go undetected."
            ),
            evidence={"log_file_validation_enabled": False},
            compliance_frameworks=list(self.compliance_frameworks),
        )
