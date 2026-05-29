"""CloudGuardIQ — Azure Monitor / Activity Log rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

_REQUIRED_OPERATIONS: set[str] = {
    "Microsoft.Authorization/policyAssignments/write",
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Sql/servers/firewallRules/write",
    "Microsoft.KeyVault/vaults/write",
}


class ActivityLogAlertsMissingRule(PolicyRule):
    """MON-001: Flag subscriptions missing alerts for critical operations."""

    rule_id: str = "MON-001"
    rule_name: str = "Critical activity log alerts missing"
    resource_types: list[str] = ["Microsoft.Insights/activityLogAlerts"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_5.2.1",
        "CIS_5.2.5",
        "NIST_AU-2",
        "SOC2_CC7.2",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when configured operations miss required ones."""
        configured = set(snapshot.config.get("monitored_operations") or [])
        missing = sorted(_REQUIRED_OPERATIONS - configured)
        if not missing:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                "Activity log alerts are not configured for critical "
                f"operations: {', '.join(missing)}."
            ),
            evidence={"missing_operations": missing},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class LogProfileRetentionRule(PolicyRule):
    """MON-002: Flag log profiles with retention below 365 days."""

    rule_id: str = "MON-002"
    rule_name: str = "Activity log retention below 365 days"
    resource_types: list[str] = ["Microsoft.Insights/logProfiles"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_5.1.2",
        "NIST_AU-11",
        "ISO_27001_A.8.15",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``retention_days`` < 365 (and not 0=forever)."""
        retention = int(snapshot.config.get("retention_days", 0) or 0)
        if retention == 0 or retention >= 365:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Log profile '{snapshot.resource_name}' retains activity "
                f"logs for {retention} days (minimum recommended: 365)."
            ),
            evidence={"retention_days": retention},
            compliance_frameworks=list(self.compliance_frameworks),
        )
