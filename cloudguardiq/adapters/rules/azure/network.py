"""CloudGuardIQ — Network security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingCategory, FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class NSGOpenSSHRule:
    """Check for NSGs allowing SSH from any source."""

    rule_id: str = "NSG_OPEN_SSH"
    resource_types: list[str] = ["Microsoft.Network/networkSecurityGroups"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate NSG for open SSH (port 22) from 0.0.0.0/0."""
        findings: list[FindingResult] = []
        rules = snapshot.properties.get("securityRules", [])
        for rule in rules:
            if (
                rule.get("destinationPortRange") == "22"
                and rule.get("sourceAddressPrefix") in ("*", "0.0.0.0/0", "Internet")
                and rule.get("access", "").lower() == "allow"
                and rule.get("direction", "").lower() == "inbound"
            ):
                name = snapshot.resource_name
                findings.append(
                    FindingResult(
                        snapshot_id=snapshot.id,
                        rule_id=self.rule_id,
                        title="NSG allows SSH from any source",
                        description=(
                            f"NSG '{name}' allows inbound SSH from any IP."
                        ),
                        severity=Severity.CRITICAL,
                        category=FindingCategory.SECURITY,
                        resource_id=snapshot.resource_id,
                        resource_type=snapshot.resource_type,
                        resource_name=name,
                        evidence={"rule": rule},
                        recommended_action="Restrict SSH to known IP ranges.",
                    )
                )
        return findings


class NSGOpenRDPRule:
    """Check for NSGs allowing RDP from any source."""

    rule_id: str = "NSG_OPEN_RDP"
    resource_types: list[str] = ["Microsoft.Network/networkSecurityGroups"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate NSG for open RDP (port 3389) from 0.0.0.0/0."""
        findings: list[FindingResult] = []
        rules = snapshot.properties.get("securityRules", [])
        for rule in rules:
            if (
                rule.get("destinationPortRange") == "3389"
                and rule.get("sourceAddressPrefix") in ("*", "0.0.0.0/0", "Internet")
                and rule.get("access", "").lower() == "allow"
                and rule.get("direction", "").lower() == "inbound"
            ):
                name = snapshot.resource_name
                findings.append(
                    FindingResult(
                        snapshot_id=snapshot.id,
                        rule_id=self.rule_id,
                        title="NSG allows RDP from any source",
                        description=(
                            f"NSG '{name}' allows inbound RDP from any IP."
                        ),
                        severity=Severity.CRITICAL,
                        category=FindingCategory.SECURITY,
                        resource_id=snapshot.resource_id,
                        resource_type=snapshot.resource_type,
                        resource_name=name,
                        evidence={"rule": rule},
                        recommended_action=(
                            "Restrict RDP to known IP ranges "
                            "or use Azure Bastion."
                        ),
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# NativeScanner PolicyRule-based network rules (NET-001 … NET-006)
# ---------------------------------------------------------------------------

_OPEN_SOURCES: set[str] = {"*", "0.0.0.0/0", "::/0", "Internet"}


def _has_inbound_allow(
    rules: list[dict[str, str]],
    *,
    port: str | None = None,
    any_port: bool = False,
) -> dict[str, str] | None:
    """Return the first inbound allow rule matching the criteria, or None.

    Args:
        rules: List of security rule dicts from the snapshot config.
        port: Specific destination port to match (e.g. ``"22"``).
        any_port: When ``True``, match rules with destination port ``"*"``.

    Returns:
        The matching rule dict, or ``None`` if no match is found.
    """
    for rule in rules:
        if (
            rule.get("access", "").lower() == "allow"
            and rule.get("direction", "").lower() == "inbound"
            and rule.get("sourceAddressPrefix") in _OPEN_SOURCES
        ):
            dest = rule.get("destinationPortRange", "")
            if port is not None and dest == port:
                return rule
            if any_port and dest == "*":
                return rule
    return None


class SSHOpenToInternetRule(PolicyRule):
    """NET-001: Flag NSGs with SSH port 22 open to the internet."""

    rule_id: str = "NET-001"
    resource_types: list[str] = ["Microsoft.Network/networkSecurityGroups"]
    rule_name: str = "SSH port 22 open to internet"
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_6.1",
        "NIST_AC-17",
        "ISO_27001_A.8.20",
        "PCI_DSS_1.3.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if any inbound rule allows port 22 from the internet."""
        rules = snapshot.config.get("securityRules", [])
        match = _has_inbound_allow(rules, port="22")
        if match is not None:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"NSG '{snapshot.resource_name}' allows SSH (port 22) "
                    "from the internet."
                ),
                evidence={"rule": match},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class RDPOpenToInternetRule(PolicyRule):
    """NET-002: Flag NSGs with RDP port 3389 open to the internet."""

    rule_id: str = "NET-002"
    resource_types: list[str] = ["Microsoft.Network/networkSecurityGroups"]
    rule_name: str = "RDP port 3389 open to internet"
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_6.2",
        "ISO_27001_A.8.20",
        "PCI_DSS_1.3.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if any inbound rule allows port 3389 from the internet."""
        rules = snapshot.config.get("securityRules", [])
        match = _has_inbound_allow(rules, port="3389")
        if match is not None:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"NSG '{snapshot.resource_name}' allows RDP (port 3389) "
                    "from the internet."
                ),
                evidence={"rule": match},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class AnyPortOpenToInternetRule(PolicyRule):
    """NET-003: Flag NSGs with any port open to the internet (catch-all)."""

    rule_id: str = "NET-003"
    resource_types: list[str] = ["Microsoft.Network/networkSecurityGroups"]
    rule_name: str = "Any port open to internet"
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_6.3",
        "ISO_27001_A.8.22",
        "PCI_DSS_1.3.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if any inbound allow rule has destination port '*'."""
        rules = snapshot.config.get("securityRules", [])
        match = _has_inbound_allow(rules, any_port=True)
        if match is not None:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"NSG '{snapshot.resource_name}' allows all ports "
                    "from the internet."
                ),
                evidence={"rule": match},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class NSGFlowLogsRule(PolicyRule):
    """NET-004: Flag NSGs without flow logs enabled."""

    rule_id: str = "NET-004"
    resource_types: list[str] = ["Microsoft.Network/networkSecurityGroups"]
    rule_name: str = "NSG flow logs not enabled"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_6.5",
        "SOC2_CC7.1",
        "ISO_27001_A.8.16",
        "PCI_DSS_10.2.1",
        "HIPAA_164.312(b)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if ``flow_logs_enabled`` is not True."""
        if snapshot.config.get("flow_logs_enabled") is not True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"NSG '{snapshot.resource_name}' does not have "
                    "flow logs enabled."
                ),
                evidence={
                    "flow_logs_enabled": snapshot.config.get("flow_logs_enabled"),
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class InboundAllowAllRule(PolicyRule):
    """NET-005: Flag NSGs with an inbound allow-all rule."""

    rule_id: str = "NET-005"
    resource_types: list[str] = ["Microsoft.Network/networkSecurityGroups"]
    rule_name: str = "Inbound allow-all rule exists"
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_6.4",
        "ISO_27001_A.8.20",
        "PCI_DSS_1.2.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if any rule allows all ports from all sources inbound."""
        rules = snapshot.config.get("securityRules", [])
        match = _has_inbound_allow(rules, any_port=True)
        if match is not None:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"NSG '{snapshot.resource_name}' has an inbound "
                    "allow-all rule."
                ),
                evidence={"rule": match},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class DDoSProtectionRule(PolicyRule):
    """NET-006: Flag internet-facing VNets without DDoS protection."""

    rule_id: str = "NET-006"
    resource_types: list[str] = ["Microsoft.Network/virtualNetworks"]
    rule_name: str = "No DDoS protection on VNet"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "NIST_SC-5",
        "ISO_27001_A.8.21",
        "PCI_DSS_1.2.1",
        "HIPAA_164.308(a)(1)(ii)(D)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if DDoS protection is disabled on an internet-facing VNet."""
        is_internet_facing = snapshot.config.get("internet_facing", False)
        if (
            is_internet_facing
            and snapshot.config.get("ddos_protection_enabled") is not True
        ):
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"VNet '{snapshot.resource_name}' is internet-facing "
                    "without DDoS protection enabled."
                ),
                evidence={
                    "ddos_protection_enabled": snapshot.config.get(
                        "ddos_protection_enabled"
                    ),
                    "internet_facing": True,
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None
