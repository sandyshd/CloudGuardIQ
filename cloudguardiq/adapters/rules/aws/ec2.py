"""CloudGuardIQ — AWS EC2 / EBS security + FinOps rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class EbsEncryptionRule(PolicyRule):
    """AWS-EC2-001: Flag EBS volumes that are not encrypted at rest."""

    rule_id: str = "AWS-EC2-001"
    rule_name: str = "EBS volume not encrypted"
    resource_types: list[str] = ["AWS::EC2::Volume"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_2.2.1",
        "NIST_SC-28",
        "SOC2_CC6.1",
        "ISO_27001_A.8.24",
        "PCI_DSS_3.5.1",
        "HIPAA_164.312(a)(2)(iv)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``encrypted`` is not True."""
        if snapshot.config.get("encrypted") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"EBS volume '{snapshot.resource_name}' is not encrypted "
                "at rest."
            ),
            evidence={"encrypted": snapshot.config.get("encrypted", False)},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class InstancePublicIpRule(PolicyRule):
    """AWS-EC2-002: Flag EC2 instances with a public IPv4 address."""

    rule_id: str = "AWS-EC2-002"
    rule_name: str = "EC2 instance has public IPv4 address"
    resource_types: list[str] = ["AWS::EC2::Instance"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_5.2",
        "NIST_SC-7",
        "ISO_27001_A.8.20",
        "PCI_DSS_1.3.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when the instance has a non-empty public IP."""
        public_ip = snapshot.config.get("public_ip_address")
        if not public_ip:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"EC2 instance '{snapshot.resource_name}' is reachable on "
                f"public IP {public_ip}."
            ),
            evidence={"public_ip_address": public_ip},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class UnattachedEbsVolumeRule(PolicyRule):
    """AWS-EC2-003: Flag EBS volumes in the ``available`` state (unattached)."""

    rule_id: str = "AWS-EC2-003"
    rule_name: str = "EBS volume is unattached"
    resource_types: list[str] = ["AWS::EC2::Volume"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = ["FINOPS_BP_1.1"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when the volume is in ``available`` state."""
        state = (snapshot.config.get("state") or "").lower()
        if state != "available":
            return None
        size_gb = snapshot.config.get("size") or 0
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"EBS volume '{snapshot.resource_name}' ({size_gb} GiB) "
                "is unattached and continues to incur storage charges."
            ),
            evidence={"state": "available", "size_gb": size_gb},
            waste_monthly_usd=float(snapshot.cost_monthly),
            compliance_frameworks=list(self.compliance_frameworks),
        )
