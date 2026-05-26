"""CloudGuardIQ — AWS Security Group rules (network exposure)."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def _ingress_rules_for_port(config: dict, port: int) -> list[dict]:
    """Return ingress rules from ``config`` that expose *port* to the internet."""
    matches: list[dict] = []
    for ingress in config.get("ingress_rules") or []:
        protocol = (ingress.get("IpProtocol") or "").lower()
        from_port = ingress.get("FromPort")
        to_port = ingress.get("ToPort")
        # protocol "-1" means all protocols / all ports
        if protocol == "-1":
            opens_port = True
        elif protocol not in ("tcp", "udp"):
            continue
        else:
            if from_port is None or to_port is None:
                continue
            opens_port = from_port <= port <= to_port
        if not opens_port:
            continue
        cidrs = [
            r.get("CidrIp") for r in (ingress.get("IpRanges") or [])
        ] + [
            r.get("CidrIpv6") for r in (ingress.get("Ipv6Ranges") or [])
        ]
        if any(cidr in PUBLIC_CIDRS for cidr in cidrs if cidr):
            matches.append(ingress)
    return matches


class SSHOpenToInternetRule(PolicyRule):
    """AWS-SG-001: Flag security groups that expose port 22 to 0.0.0.0/0."""

    rule_id: str = "AWS-SG-001"
    rule_name: str = "Security group exposes SSH (22) to the internet"
    resource_types: list[str] = ["AWS::EC2::SecurityGroup"]
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_5.2",
        "NIST_SC-7",
        "SOC2_CC6.6",
        "ISO_27001_A.8.20",
        "PCI_DSS_1.3.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when any ingress rule opens port 22 publicly."""
        matches = _ingress_rules_for_port(snapshot.config, 22)
        if not matches:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Security group '{snapshot.resource_name}' allows SSH "
                "(port 22) from 0.0.0.0/0."
            ),
            evidence={"matched_rules": matches},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class RDPOpenToInternetRule(PolicyRule):
    """AWS-SG-002: Flag security groups that expose port 3389 to 0.0.0.0/0."""

    rule_id: str = "AWS-SG-002"
    rule_name: str = "Security group exposes RDP (3389) to the internet"
    resource_types: list[str] = ["AWS::EC2::SecurityGroup"]
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_5.2",
        "NIST_SC-7",
        "SOC2_CC6.6",
        "ISO_27001_A.8.20",
        "PCI_DSS_1.3.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when any ingress rule opens port 3389 publicly."""
        matches = _ingress_rules_for_port(snapshot.config, 3389)
        if not matches:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Security group '{snapshot.resource_name}' allows RDP "
                "(port 3389) from 0.0.0.0/0."
            ),
            evidence={"matched_rules": matches},
            compliance_frameworks=list(self.compliance_frameworks),
        )
