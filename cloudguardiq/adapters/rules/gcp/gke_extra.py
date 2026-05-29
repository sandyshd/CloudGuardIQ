"""CloudGuardIQ -- GCP GKE extras (workload identity, auto-upgrade, binary auth)."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class GkeWorkloadIdentityRule(PolicyRule):
    """GCP-GKE-004: Flag GKE clusters without Workload Identity enabled."""

    rule_id: str = "GCP-GKE-004"
    rule_name: str = "GKE Workload Identity disabled"
    resource_types: list[str] = ["google.container.Cluster"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["CIS_GKE_5.2.2", "NIST_AC-6"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when no workload identity pool is configured."""
        if snapshot.config.get("workload_identity_pool"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"GKE cluster '{snapshot.resource_name}' has not enabled "
                "Workload Identity."
            ),
            evidence={"workload_identity_pool": None},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class GkeAutoUpgradeDisabledRule(PolicyRule):
    """GCP-GKE-005: Flag GKE node pools without auto-upgrade."""

    rule_id: str = "GCP-GKE-005"
    rule_name: str = "GKE node pool auto-upgrade disabled"
    resource_types: list[str] = ["google.container.NodePool"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = ["CIS_GKE_5.5.1", "NIST_SI-2"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``auto_upgrade`` is False."""
        if snapshot.config.get("auto_upgrade") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Node pool '{snapshot.resource_name}' does not auto-upgrade. "
                "Nodes may run outdated, vulnerable versions."
            ),
            evidence={"auto_upgrade": snapshot.config.get("auto_upgrade", False)},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class GkeBinaryAuthorizationRule(PolicyRule):
    """GCP-GKE-006: Flag GKE clusters without Binary Authorization."""

    rule_id: str = "GCP-GKE-006"
    rule_name: str = "GKE Binary Authorization disabled"
    resource_types: list[str] = ["google.container.Cluster"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["CIS_GKE_5.10.4", "NIST_CM-5"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when Binary Authorization is not enforced."""
        mode = str(snapshot.config.get("binary_authorization_mode", "")).upper()
        if mode == "PROJECT_SINGLETON_POLICY_ENFORCE":
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"GKE cluster '{snapshot.resource_name}' does not enforce "
                "Binary Authorization on image deployment."
            ),
            evidence={"binary_authorization_mode": mode or "DISABLED"},
            compliance_frameworks=list(self.compliance_frameworks),
        )
