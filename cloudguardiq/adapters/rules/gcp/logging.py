"""CloudGuardIQ -- GCP Cloud Logging rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class LoggingSinkMissingRule(PolicyRule):
    """GCP-LOG-001: Flag projects missing a project-wide log sink."""

    rule_id: str = "GCP-LOG-001"
    rule_name: str = "No project-wide log sink configured"
    resource_types: list[str] = ["google.logging.Project"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_GCP_2.2",
        "NIST_AU-2",
        "SOC2_CC7.2",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when no sink with ``filter='*'`` exists."""
        sinks = snapshot.config.get("sinks") or []
        catch_all = any(
            str(sink.get("filter", "")).strip() in ("", "*") for sink in sinks
        )
        if catch_all:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Project '{snapshot.resource_name}' has no project-wide "
                "log sink exporting all entries."
            ),
            evidence={"sink_count": len(sinks)},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class LoggingRetentionRule(PolicyRule):
    """GCP-LOG-002: Flag log buckets with retention below 365 days."""

    rule_id: str = "GCP-LOG-002"
    rule_name: str = "Log bucket retention below 365 days"
    resource_types: list[str] = ["google.logging.LogBucket"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_GCP_2.3",
        "NIST_AU-11",
        "ISO_27001_A.8.15",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``retention_days`` < 365."""
        retention = int(snapshot.config.get("retention_days", 0) or 0)
        if retention >= 365:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Log bucket '{snapshot.resource_name}' retains entries "
                f"for {retention} days (minimum recommended: 365)."
            ),
            evidence={"retention_days": retention},
            compliance_frameworks=list(self.compliance_frameworks),
        )
