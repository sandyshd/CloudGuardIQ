"""CloudGuardIQ — AWS ELB / ALB rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class ElbHttpListenerRule(PolicyRule):
    """AWS-ELB-001: Flag load balancers with non-HTTPS listeners."""

    rule_id: str = "AWS-ELB-001"
    rule_name: str = "Load balancer accepts unencrypted HTTP traffic"
    resource_types: list[str] = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "NIST_SC-8",
        "PCI_DSS_4.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when any listener uses HTTP (not HTTPS/TLS)."""
        listeners = snapshot.config.get("listeners") or []
        bad = [
            listener
            for listener in listeners
            if str(listener.get("protocol", "")).upper() in ("HTTP", "TCP")
        ]
        if not bad:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Load balancer '{snapshot.resource_name}' has "
                f"{len(bad)} non-encrypted listener(s)."
            ),
            evidence={"insecure_listeners": bad},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class ElbAccessLogsDisabledRule(PolicyRule):
    """AWS-ELB-002: Flag load balancers with access logs disabled."""

    rule_id: str = "AWS-ELB-002"
    rule_name: str = "Load balancer access logs disabled"
    resource_types: list[str] = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "NIST_AU-2",
        "PCI_DSS_10.2",
        "ISO_27001_A.8.15",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when access logs are disabled."""
        if snapshot.config.get("access_logs_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Load balancer '{snapshot.resource_name}' does not have "
                "access logs enabled."
            ),
            evidence={
                "access_logs_enabled": snapshot.config.get(
                    "access_logs_enabled", False
                ),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class ElbDeletionProtectionRule(PolicyRule):
    """AWS-ELB-003: Flag load balancers without deletion protection."""

    rule_id: str = "AWS-ELB-003"
    rule_name: str = "Load balancer deletion protection disabled"
    resource_types: list[str] = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
    severity: Severity = Severity.LOW
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = ["NIST_CP-10", "ISO_27001_A.8.13"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when deletion protection is disabled."""
        if snapshot.config.get("deletion_protection_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Load balancer '{snapshot.resource_name}' can be deleted "
                "accidentally — enable deletion protection."
            ),
            evidence={
                "deletion_protection_enabled": snapshot.config.get(
                    "deletion_protection_enabled", False
                ),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )
