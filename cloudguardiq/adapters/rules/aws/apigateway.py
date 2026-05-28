"""CloudGuardIQ — AWS API Gateway rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class ApiGatewayLoggingDisabledRule(PolicyRule):
    """AWS-APIGW-001: Flag REST API stages without execution logging."""

    rule_id: str = "AWS-APIGW-001"
    rule_name: str = "API Gateway stage logging disabled"
    resource_types: list[str] = ["AWS::ApiGateway::Stage"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = ["NIST_AU-2", "PCI_DSS_10.2"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when no log level is configured."""
        level = str(snapshot.config.get("logging_level", "")).upper()
        if level in ("INFO", "ERROR"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"API Gateway stage '{snapshot.resource_name}' has no "
                "execution logging configured."
            ),
            evidence={"logging_level": level or "OFF"},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class ApiGatewayNoWafRule(PolicyRule):
    """AWS-APIGW-002: Flag REST API stages without an associated WAF web ACL."""

    rule_id: str = "AWS-APIGW-002"
    rule_name: str = "API Gateway stage has no WAF"
    resource_types: list[str] = ["AWS::ApiGateway::Stage"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SC-7", "PCI_DSS_6.4.2"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``web_acl_arn`` is empty."""
        if snapshot.config.get("web_acl_arn"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"API Gateway stage '{snapshot.resource_name}' is not "
                "protected by an AWS WAF web ACL."
            ),
            evidence={"web_acl_arn": None},
            compliance_frameworks=list(self.compliance_frameworks),
        )
