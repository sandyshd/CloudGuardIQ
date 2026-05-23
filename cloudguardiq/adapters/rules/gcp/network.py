"""CloudGuardIQ -- GCP VPC firewall rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


def _matches_port(allowed: list[dict], port: int) -> bool:
    """Return True when *allowed* includes ``tcp`` covering *port*."""
    for entry in allowed or []:
        protocol = str(entry.get("protocol", "")).lower()
        if protocol not in ("tcp", "all"):
            continue
        ports = entry.get("ports") or []
        if not ports:
            # No ports == all ports
            return True
        for spec in ports:
            spec = str(spec)
            if "-" in spec:
                lo, hi = spec.split("-", 1)
                try:
                    if int(lo) <= port <= int(hi):
                        return True
                except ValueError:
                    continue
            else:
                try:
                    if int(spec) == port:
                        return True
                except ValueError:
                    continue
    return False


def _is_open_to_internet(snapshot: ResourceSnapshot) -> bool:
    """True when the firewall rule is enabled, ingress, and 0.0.0.0/0."""
    if snapshot.config.get("disabled"):
        return False
    if str(snapshot.config.get("direction", "")).upper() != "INGRESS":
        return False
    source_ranges = snapshot.config.get("source_ranges") or []
    return "0.0.0.0/0" in source_ranges


class FirewallSshOpenRule(PolicyRule):
    """GCP-NET-001: Flag firewall rules that expose SSH (22) to the internet."""

    rule_id: str = "GCP-NET-001"
    rule_name: str = "Firewall allows SSH (22) from 0.0.0.0/0"
    resource_types: list[str] = ["google.compute.Firewall"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["CIS_GCP_3.6", "NIST_SC-7"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when the rule opens TCP/22 to the world."""
        if not _is_open_to_internet(snapshot):
            return None
        if not _matches_port(snapshot.config.get("allowed") or [], 22):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Firewall rule '{snapshot.resource_name}' permits SSH from "
                "0.0.0.0/0. Restrict source ranges or use IAP tunneling."
            ),
            evidence={"source_ranges": snapshot.config.get("source_ranges", [])},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class FirewallRdpOpenRule(PolicyRule):
    """GCP-NET-002: Flag firewall rules that expose RDP (3389) to the internet."""

    rule_id: str = "GCP-NET-002"
    rule_name: str = "Firewall allows RDP (3389) from 0.0.0.0/0"
    resource_types: list[str] = ["google.compute.Firewall"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["CIS_GCP_3.7", "NIST_SC-7"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when the rule opens TCP/3389 to the world."""
        if not _is_open_to_internet(snapshot):
            return None
        if not _matches_port(snapshot.config.get("allowed") or [], 3389):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Firewall rule '{snapshot.resource_name}' permits RDP from "
                "0.0.0.0/0. Restrict source ranges or use IAP tunneling."
            ),
            evidence={"source_ranges": snapshot.config.get("source_ranges", [])},
            compliance_frameworks=list(self.compliance_frameworks),
        )
