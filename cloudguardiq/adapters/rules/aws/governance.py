"""CloudGuardIQ — AWS Config / IAM extras / S3 extras."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class ConfigRecorderDisabledRule(PolicyRule):
    """AWS-CFG-001: Flag accounts where AWS Config recorder is disabled."""

    rule_id: str = "AWS-CFG-001"
    rule_name: str = "AWS Config recorder disabled"
    resource_types: list[str] = ["AWS::Config::ConfigurationRecorder"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_AWS_3.5",
        "NIST_CM-8",
        "PCI_DSS_10.2",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when recorder is not recording all resources."""
        recording = bool(snapshot.config.get("recording"))
        all_resources = bool(snapshot.config.get("all_supported"))
        if recording and all_resources:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"AWS Config recorder '{snapshot.resource_name}' is not "
                "actively recording all supported resource types."
            ),
            evidence={"recording": recording, "all_supported": all_resources},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class IamPasswordPolicyWeakRule(PolicyRule):
    """AWS-IAM-003: Flag account password policies that are weaker than CIS baseline."""

    rule_id: str = "AWS-IAM-003"
    rule_name: str = "IAM password policy is weak"
    resource_types: list[str] = ["AWS::IAM::PasswordPolicy"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_AWS_1.5",
        "NIST_IA-5",
        "PCI_DSS_8.3.6",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when min length < 14 or reuse window < 24."""
        cfg = snapshot.config
        weak_reasons: list[str] = []
        if int(cfg.get("minimum_password_length", 0) or 0) < 14:
            weak_reasons.append("minimum_password_length<14")
        if not cfg.get("require_symbols"):
            weak_reasons.append("require_symbols=false")
        if not cfg.get("require_numbers"):
            weak_reasons.append("require_numbers=false")
        reuse = int(cfg.get("password_reuse_prevention", 0) or 0)
        if reuse < 24:
            weak_reasons.append("password_reuse_prevention<24")
        if not weak_reasons:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                "Account password policy is weaker than CIS baseline: "
                + ", ".join(weak_reasons)
            ),
            evidence={"weaknesses": weak_reasons},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class IamAccessKeyAgeRule(PolicyRule):
    """AWS-IAM-004: Flag IAM users with an active access key older than 90 days."""

    rule_id: str = "AWS-IAM-004"
    rule_name: str = "IAM access key older than 90 days"
    resource_types: list[str] = ["AWS::IAM::User"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_AWS_1.14",
        "NIST_IA-5",
        "PCI_DSS_8.3.9",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when any active key has ``age_days`` > 90."""
        keys = snapshot.config.get("access_keys") or []
        stale = [
            key
            for key in keys
            if str(key.get("status", "")).lower() == "active"
            and int(key.get("age_days", 0) or 0) > 90
        ]
        if not stale:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"IAM user '{snapshot.resource_name}' has {len(stale)} "
                "active access key(s) older than 90 days."
            ),
            evidence={"stale_keys": stale},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class S3VersioningDisabledRule(PolicyRule):
    """AWS-S3-004: Flag S3 buckets without versioning enabled."""

    rule_id: str = "AWS-S3-004"
    rule_name: str = "S3 bucket versioning disabled"
    resource_types: list[str] = ["AWS::S3::Bucket"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_AWS_2.1.3",
        "NIST_CP-9",
        "ISO_27001_A.8.13",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when versioning status is not Enabled."""
        status = str(snapshot.config.get("versioning_status", "")).lower()
        if status == "enabled":
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"S3 bucket '{snapshot.resource_name}' does not have "
                "versioning enabled."
            ),
            evidence={"versioning_status": status or "disabled"},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class S3LoggingDisabledRule(PolicyRule):
    """AWS-S3-005: Flag S3 buckets without server access logging."""

    rule_id: str = "AWS-S3-005"
    rule_name: str = "S3 bucket access logging disabled"
    resource_types: list[str] = ["AWS::S3::Bucket"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_AWS_2.1.2",
        "NIST_AU-2",
        "PCI_DSS_10.2",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when no logging target bucket is set."""
        if snapshot.config.get("logging_target_bucket"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"S3 bucket '{snapshot.resource_name}' does not deliver "
                "server access logs."
            ),
            evidence={"logging_target_bucket": None},
            compliance_frameworks=list(self.compliance_frameworks),
        )
