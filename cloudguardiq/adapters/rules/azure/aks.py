"""CloudGuardIQ — Azure Kubernetes Service (AKS) security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class AKSRBACDisabledRule(PolicyRule):
    """AKS-001: Flag AKS clusters without Kubernetes RBAC enabled."""

    rule_id: str = "AKS-001"
    rule_name: str = "AKS cluster RBAC disabled"
    resource_types: list[str] = ["Microsoft.ContainerService/managedClusters"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AKS_5.1.3",
        "NIST_AC-3",
        "ISO_27001_A.8.3",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``enable_rbac`` is False."""
        if snapshot.config.get("enable_rbac") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"AKS cluster '{snapshot.resource_name}' does not have "
                "Kubernetes RBAC enabled."
            ),
            evidence={"enable_rbac": snapshot.config.get("enable_rbac", False)},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class AKSPublicApiServerRule(PolicyRule):
    """AKS-002: Flag AKS clusters with a public API server."""

    rule_id: str = "AKS-002"
    rule_name: str = "AKS API server publicly exposed"
    resource_types: list[str] = ["Microsoft.ContainerService/managedClusters"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AKS_5.4.2",
        "NIST_SC-7",
        "ISO_27001_A.8.20",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when cluster is not private and lacks IP ranges."""
        private = bool(snapshot.config.get("private_cluster"))
        if private:
            return None
        ip_ranges = snapshot.config.get("authorized_ip_ranges") or []
        if ip_ranges:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"AKS cluster '{snapshot.resource_name}' API server is "
                "reachable from the internet with no authorized IP ranges."
            ),
            evidence={
                "private_cluster": private,
                "authorized_ip_ranges": list(ip_ranges),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class AKSNetworkPolicyMissingRule(PolicyRule):
    """AKS-003: Flag AKS clusters without a Kubernetes network policy."""

    rule_id: str = "AKS-003"
    rule_name: str = "AKS cluster has no network policy"
    resource_types: list[str] = ["Microsoft.ContainerService/managedClusters"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AKS_5.3.2",
        "NIST_SC-7(5)",
        "ISO_27001_A.8.22",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when no network policy plugin is configured."""
        policy = str(snapshot.config.get("network_policy", "")).lower()
        if policy in ("azure", "calico", "cilium"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"AKS cluster '{snapshot.resource_name}' has no network "
                "policy configured. Pod-to-pod traffic is unrestricted."
            ),
            evidence={"network_policy": policy or "none"},
            compliance_frameworks=list(self.compliance_frameworks),
        )
