"""CloudGuardIQ — AWS Lambda security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

# Runtimes officially deprecated or in deprecation by AWS Lambda.
_DEPRECATED_RUNTIMES: set[str] = {
    "nodejs",
    "nodejs4.3",
    "nodejs6.10",
    "nodejs8.10",
    "nodejs10.x",
    "nodejs12.x",
    "nodejs14.x",
    "nodejs16.x",
    "python2.7",
    "python3.6",
    "python3.7",
    "python3.8",
    "ruby2.5",
    "ruby2.7",
    "dotnetcore1.0",
    "dotnetcore2.0",
    "dotnetcore2.1",
    "dotnetcore3.1",
    "dotnet5.0",
    "dotnet6",
    "go1.x",
    "java8",
}


class LambdaEnvVarKmsKeyRule(PolicyRule):
    """AWS-LAM-001: Flag Lambda functions whose env vars use the default KMS key."""

    rule_id: str = "AWS-LAM-001"
    rule_name: str = "Lambda env vars not encrypted with CMK"
    resource_types: list[str] = ["AWS::Lambda::Function"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_3.0_4.1",
        "NIST_SC-28",
        "ISO_27001_A.8.24",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when env vars exist but no customer KMS key is set."""
        env_vars = snapshot.config.get("environment_variables") or {}
        if not env_vars:
            return None
        kms_key = snapshot.config.get("kms_key_arn") or ""
        if kms_key:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Lambda '{snapshot.resource_name}' stores environment "
                "variables encrypted with the default AWS-managed key."
            ),
            evidence={
                "env_var_count": len(env_vars),
                "kms_key_arn": kms_key,
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class LambdaPublicFunctionUrlRule(PolicyRule):
    """AWS-LAM-002: Flag Lambda Function URLs that allow anonymous (NONE) auth."""

    rule_id: str = "AWS-LAM-002"
    rule_name: str = "Lambda Function URL is public"
    resource_types: list[str] = ["AWS::Lambda::Function"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "NIST_AC-3",
        "ISO_27001_A.8.3",
        "PCI_DSS_7.1.2",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when function URL exists with ``AuthType=NONE``."""
        url_config = snapshot.config.get("function_url_config") or {}
        if not url_config:
            return None
        auth_type = str(url_config.get("auth_type", "")).upper()
        if auth_type != "NONE":
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Lambda '{snapshot.resource_name}' exposes a Function URL "
                "with AuthType=NONE (anonymous access)."
            ),
            evidence={"function_url_config": url_config},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class LambdaOutdatedRuntimeRule(PolicyRule):
    """AWS-LAM-003: Flag Lambda functions using a deprecated runtime."""

    rule_id: str = "AWS-LAM-003"
    rule_name: str = "Lambda uses deprecated runtime"
    resource_types: list[str] = ["AWS::Lambda::Function"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "NIST_SI-2",
        "ISO_27001_A.8.8",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when the runtime is in the deprecated list."""
        runtime = str(snapshot.config.get("runtime", "")).strip().lower()
        if not runtime or runtime not in _DEPRECATED_RUNTIMES:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Lambda '{snapshot.resource_name}' uses the deprecated "
                f"runtime '{runtime}'. Upgrade to a supported version."
            ),
            evidence={"runtime": runtime},
            compliance_frameworks=list(self.compliance_frameworks),
        )
