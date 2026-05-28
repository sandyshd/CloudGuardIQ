"""CloudGuardIQ -- GCP network extras (default deny, broad ranges)."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

_OPEN_SOURCES: set[str] = {"0.0.0.0/0", "::/0"}


class FirewallAnyPortOpenRule(PolicyRule):
    """GCP-NET-003: Flag firewall rules allowing any port from the internet."""

    rule_id: str = "GCP-NET-003"
    rule_name: str = "Firewall rule allows any port from internet"
    resource_types: list[str] = ["google.compute.Firewall"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_3.7",
        "NIST_SC-7",
        "PCI_DSS_1.2.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when direction=INGRESS, source=0.0.0.0/0, ports=any."""
        if str(snapshot.config.get("direction", "")).upper() != "INGRESS":
            return None
        sources = set(snapshot.config.get("source_ranges") or [])
        if not (sources & _OPEN_SOURCES):
            return None
        allowed = snapshot.config.get("allowed") or []
        any_proto = any(
            str(item.get("IPProtocol", "")).lower() == "all"
            or not item.get("ports")
            for item in allowed
        )
        if not any_proto:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Firewall '{snapshot.resource_name}' allows traffic on any "
                "protocol/port from the internet."
            ),
            evidence={"source_ranges": list(sources), "allowed": allowed},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class FirewallLoggingDisabledRule(PolicyRule):
    """GCP-NET-004: Flag firewall rules without logging enabled."""

    rule_id: str = "GCP-NET-004"
    rule_name: str = "Firewall rule has logging disabled"
    resource_types: list[str] = ["google.compute.Firewall"]
    severity: Severity = Severity.LOW
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = ["NIST_AU-2", "ISO_27001_A.8.15"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``log_config_enabled`` is False."""
        if snapshot.config.get("log_config_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Firewall '{snapshot.resource_name}' does not log "
                "connection events."
            ),
            evidence={
                "log_config_enabled": snapshot.config.get(
                    "log_config_enabled", False
                ),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )
