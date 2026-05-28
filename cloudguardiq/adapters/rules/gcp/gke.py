"""CloudGuardIQ -- GCP GKE (Kubernetes Engine) security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class GkePrivateClusterRule(PolicyRule):
    """GCP-GKE-001: Flag GKE clusters that are not private."""

    rule_id: str = "GCP-GKE-001"
    rule_name: str = "GKE cluster nodes have public IPs"
    resource_types: list[str] = ["google.container.Cluster"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GKE_5.6.5",
        "NIST_SC-7",
        "ISO_27001_A.8.20",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``enable_private_nodes`` is False."""
        if snapshot.config.get("enable_private_nodes") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"GKE cluster '{snapshot.resource_name}' is not private. "
                "Nodes are assigned public IP addresses."
            ),
            evidence={
                "enable_private_nodes": snapshot.config.get(
                    "enable_private_nodes", False
                ),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class GkeLoggingDisabledRule(PolicyRule):
    """GCP-GKE-002: Flag GKE clusters with Cloud Logging disabled."""

    rule_id: str = "GCP-GKE-002"
    rule_name: str = "GKE Cloud Logging disabled"
    resource_types: list[str] = ["google.container.Cluster"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_GKE_5.7.1",
        "NIST_AU-2",
        "SOC2_CC7.2",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``logging_service`` is none/empty."""
        service = str(snapshot.config.get("logging_service", "")).lower()
        if service and service != "none":
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"GKE cluster '{snapshot.resource_name}' has Cloud Logging "
                "disabled."
            ),
            evidence={"logging_service": service or "none"},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class GkeNetworkPolicyRule(PolicyRule):
    """GCP-GKE-003: Flag GKE clusters without a network policy plugin."""

    rule_id: str = "GCP-GKE-003"
    rule_name: str = "GKE network policy not enabled"
    resource_types: list[str] = ["google.container.Cluster"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GKE_5.6.7",
        "NIST_SC-7(5)",
        "ISO_27001_A.8.22",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``network_policy_enabled`` is False."""
        if snapshot.config.get("network_policy_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"GKE cluster '{snapshot.resource_name}' does not have a "
                "network policy plugin enabled. Pod traffic is unrestricted."
            ),
            evidence={
                "network_policy_enabled": snapshot.config.get(
                    "network_policy_enabled", False
                ),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )
