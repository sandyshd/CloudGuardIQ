"""CloudGuardIQ — AWS VPC rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class VpcFlowLogsDisabledRule(PolicyRule):
    """AWS-VPC-001: Flag VPCs without flow logs enabled."""

    rule_id: str = "AWS-VPC-001"
    rule_name: str = "VPC flow logs disabled"
    resource_types: list[str] = ["AWS::EC2::VPC"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_AWS_3.9",
        "NIST_AU-2",
        "PCI_DSS_10.2",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``flow_logs_enabled`` is False."""
        if snapshot.config.get("flow_logs_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"VPC '{snapshot.resource_name}' does not have flow logs "
                "enabled."
            ),
            evidence={
                "flow_logs_enabled": snapshot.config.get(
                    "flow_logs_enabled", False
                ),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class DefaultSecurityGroupOpenRule(PolicyRule):
    """AWS-VPC-002: Flag default security groups that allow any traffic."""

    rule_id: str = "AWS-VPC-002"
    rule_name: str = "Default security group allows traffic"
    resource_types: list[str] = ["AWS::EC2::SecurityGroup"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_5.3",
        "NIST_SC-7",
        "PCI_DSS_1.2.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when the *default* SG has any ingress/egress rules."""
        name = str(snapshot.config.get("group_name") or snapshot.resource_name)
        if name.lower() != "default":
            return None
        ingress = snapshot.config.get("ip_permissions") or []
        egress = snapshot.config.get("ip_permissions_egress") or []
        if not ingress and not egress:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Default security group '{snapshot.resource_name}' has "
                f"{len(ingress)} ingress and {len(egress)} egress rule(s). "
                "It should not allow any traffic."
            ),
            evidence={"ingress_count": len(ingress), "egress_count": len(egress)},
            compliance_frameworks=list(self.compliance_frameworks),
        )
