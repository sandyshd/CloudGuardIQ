"""CloudGuardIQ — AWS IAM security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class RootAccessKeysRule(PolicyRule):
    """AWS-IAM-001: Flag the root account when it has access keys."""

    rule_id: str = "AWS-IAM-001"
    rule_name: str = "Root account has access keys"
    resource_types: list[str] = ["AWS::IAM::AccountSummary"]
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_1.4",
        "NIST_AC-6",
        "SOC2_CC6.1",
        "ISO_27001_A.8.2",
        "PCI_DSS_7.2.5",
        "HIPAA_164.312(a)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``AccountAccessKeysPresent`` > 0."""
        summary = snapshot.config.get("summary_map") or {}
        keys_present = int(summary.get("AccountAccessKeysPresent", 0) or 0)
        if keys_present <= 0:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                "The AWS account root user has active access keys. The "
                "root user must never use long-lived credentials."
            ),
            evidence={"AccountAccessKeysPresent": keys_present},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class IamUserNoMfaRule(PolicyRule):
    """AWS-IAM-002: Flag IAM users with console access but no MFA device."""

    rule_id: str = "AWS-IAM-002"
    rule_name: str = "IAM user with console access lacks MFA"
    resource_types: list[str] = ["AWS::IAM::User"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_1.10",
        "NIST_IA-2",
        "SOC2_CC6.1",
        "ISO_27001_A.8.5",
        "PCI_DSS_8.4.2",
        "HIPAA_164.312(d)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``password_enabled`` and ``mfa_active is False``."""
        cfg = snapshot.config
        if cfg.get("password_enabled") is not True:
            return None
        if cfg.get("mfa_active") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"IAM user '{snapshot.resource_name}' has console access "
                "enabled but no MFA device registered."
            ),
            evidence={
                "password_enabled": True,
                "mfa_active": bool(cfg.get("mfa_active", False)),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )
