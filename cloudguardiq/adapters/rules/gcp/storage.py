"""CloudGuardIQ -- GCS bucket security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class BucketPublicAccessRule(PolicyRule):
    """GCP-GCS-001: Flag GCS buckets exposing data to ``allUsers`` /
    ``allAuthenticatedUsers`` via IAM."""

    rule_id: str = "GCP-GCS-001"
    rule_name: str = "GCS bucket is public via IAM"
    resource_types: list[str] = ["google.storage.Bucket"]
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_5.1",
        "NIST_AC-3",
        "SOC2_CC6.1",
        "ISO_27001_A.8.20",
        "PCI_DSS_1.3.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``public_iam_member`` is True."""
        if not snapshot.config.get("public_iam_member"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"GCS bucket '{snapshot.resource_name}' grants access to "
                "allUsers or allAuthenticatedUsers."
            ),
            evidence={"public_iam_member": True},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class BucketUniformAccessRule(PolicyRule):
    """GCP-GCS-002: Flag GCS buckets that do not use uniform bucket-level
    access (which disables legacy ACLs)."""

    rule_id: str = "GCP-GCS-002"
    rule_name: str = "GCS bucket allows legacy ACLs (no uniform access)"
    resource_types: list[str] = ["google.storage.Bucket"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_5.2",
        "ISO_27001_A.8.3",
        "PCI_DSS_7.2.4",
        "HIPAA_164.312(a)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when uniform bucket-level access is disabled."""
        if snapshot.config.get("uniform_bucket_level_access") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"GCS bucket '{snapshot.resource_name}' allows legacy object "
                "ACLs. Enable uniform bucket-level access."
            ),
            evidence={"uniform_bucket_level_access": False},
            compliance_frameworks=list(self.compliance_frameworks),
        )
