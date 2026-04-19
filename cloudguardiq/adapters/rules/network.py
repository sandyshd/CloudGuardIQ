"""CloudGuardIQ — Network security rules."""

from __future__ import annotations

from cloudguardiq.core.enums import FindingCategory, Severity
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
