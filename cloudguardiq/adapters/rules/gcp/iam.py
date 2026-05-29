"""CloudGuardIQ -- GCP IAM service-account rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class ServiceAccountUserManagedKeyRule(PolicyRule):
    """GCP-IAM-001: Flag service accounts with user-managed (downloadable)
    keys. CIS recommends using short-lived workload-identity credentials."""

    rule_id: str = "GCP-IAM-001"
    rule_name: str = "Service account has user-managed keys"
    resource_types: list[str] = ["google.iam.ServiceAccount"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_1.4",
        "NIST_IA-5",
        "ISO_27001_A.5.17",
        "PCI_DSS_8.3.1",
        "HIPAA_164.308(a)(5)(ii)(D)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``user_managed_keys > 0``."""
        keys = int(snapshot.config.get("user_managed_keys") or 0)
        if keys <= 0:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Service account '{snapshot.resource_name}' has {keys} "
                "user-managed key(s). Rotate to workload-identity federation."
            ),
            evidence={"user_managed_keys": keys},
            compliance_frameworks=list(self.compliance_frameworks),
        )
