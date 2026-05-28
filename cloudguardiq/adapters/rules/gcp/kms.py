"""CloudGuardIQ -- GCP KMS rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class KmsKeyRotationRule(PolicyRule):
    """GCP-KMS-001: Flag KMS crypto keys with rotation period > 90 days."""

    rule_id: str = "GCP-KMS-001"
    rule_name: str = "KMS crypto key rotation period too long"
    resource_types: list[str] = ["google.kms.CryptoKey"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_1.10",
        "NIST_SC-12",
        "ISO_27001_A.8.24",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``rotation_period_days`` > 90 or unset."""
        period = snapshot.config.get("rotation_period_days")
        if period is not None and int(period) <= 90:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"KMS key '{snapshot.resource_name}' rotates every "
                f"{period if period is not None else 'never'} days "
                "(CIS recommends ≤90)."
            ),
            evidence={"rotation_period_days": period},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class KmsKeyPublicAccessRule(PolicyRule):
    """GCP-KMS-002: Flag KMS keys with allUsers in IAM policy."""

    rule_id: str = "GCP-KMS-002"
    rule_name: str = "KMS key IAM grants public access"
    resource_types: list[str] = ["google.kms.CryptoKey"]
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["CIS_GCP_1.9", "NIST_AC-3"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when any binding contains a public member."""
        bindings = snapshot.config.get("iam_bindings") or []
        public = sorted(
            {
                member
                for binding in bindings
                for member in (binding.get("members") or [])
                if member in {"allUsers", "allAuthenticatedUsers"}
            }
        )
        if not public:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"KMS key '{snapshot.resource_name}' IAM policy grants "
                f"access to {', '.join(public)}."
            ),
            evidence={"public_members": public},
            compliance_frameworks=list(self.compliance_frameworks),
        )
