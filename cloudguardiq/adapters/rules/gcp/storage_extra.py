"""CloudGuardIQ -- GCP storage extras (versioning, retention, uniform IAM)."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class BucketVersioningDisabledRule(PolicyRule):
    """GCP-GCS-003: Flag GCS buckets without versioning enabled."""

    rule_id: str = "GCP-GCS-003"
    rule_name: str = "GCS bucket versioning disabled"
    resource_types: list[str] = ["google.storage.Bucket"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = ["NIST_CP-9", "ISO_27001_A.8.13"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``versioning_enabled`` is not True."""
        if snapshot.config.get("versioning_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"GCS bucket '{snapshot.resource_name}' does not have "
                "object versioning enabled."
            ),
            evidence={
                "versioning_enabled": snapshot.config.get(
                    "versioning_enabled", False
                ),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class BucketRetentionPolicyRule(PolicyRule):
    """GCP-GCS-004: Flag GCS buckets without a locked retention policy."""

    rule_id: str = "GCP-GCS-004"
    rule_name: str = "GCS bucket retention policy not locked"
    resource_types: list[str] = ["google.storage.Bucket"]
    severity: Severity = Severity.LOW
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = ["NIST_AU-11", "ISO_27001_A.8.15"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when retention is missing or unlocked."""
        retention = snapshot.config.get("retention_policy") or {}
        if retention.get("is_locked") is True and int(
            retention.get("retention_period_days", 0) or 0
        ) > 0:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"GCS bucket '{snapshot.resource_name}' does not have a "
                "locked retention policy."
            ),
            evidence={"retention_policy": retention},
            compliance_frameworks=list(self.compliance_frameworks),
        )
