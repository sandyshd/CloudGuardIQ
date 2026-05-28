"""CloudGuardIQ -- GCP Pub/Sub rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class PubSubTopicCmekRule(PolicyRule):
    """GCP-PS-001: Flag Pub/Sub topics without a CMEK key."""

    rule_id: str = "GCP-PS-001"
    rule_name: str = "Pub/Sub topic not CMEK-encrypted"
    resource_types: list[str] = ["google.pubsub.Topic"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SC-28", "ISO_27001_A.8.24"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``kms_key_name`` is not set."""
        if snapshot.config.get("kms_key_name"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Pub/Sub topic '{snapshot.resource_name}' uses the "
                "Google-managed key for message encryption."
            ),
            evidence={"kms_key_name": None},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class PubSubTopicPublicAccessRule(PolicyRule):
    """GCP-PS-002: Flag Pub/Sub topics with allUsers in IAM bindings."""

    rule_id: str = "GCP-PS-002"
    rule_name: str = "Pub/Sub topic IAM grants public access"
    resource_types: list[str] = ["google.pubsub.Topic"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_AC-3", "ISO_27001_A.5.15"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when bindings include a public member."""
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
                f"Pub/Sub topic '{snapshot.resource_name}' IAM policy "
                f"grants access to {', '.join(public)}."
            ),
            evidence={"public_members": public},
            compliance_frameworks=list(self.compliance_frameworks),
        )
