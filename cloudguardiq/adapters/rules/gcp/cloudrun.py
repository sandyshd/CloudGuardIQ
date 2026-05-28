"""CloudGuardIQ -- GCP Cloud Run rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class CloudRunIngressRule(PolicyRule):
    """GCP-CR-001: Flag Cloud Run services with ingress=all."""

    rule_id: str = "GCP-CR-001"
    rule_name: str = "Cloud Run service ingress is public"
    resource_types: list[str] = ["google.run.Service"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SC-7", "ISO_27001_A.8.20"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ingress is set to ``all``."""
        ingress = str(snapshot.config.get("ingress", "")).lower()
        if ingress and ingress != "all":
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Cloud Run service '{snapshot.resource_name}' accepts "
                "traffic from any source (ingress=all)."
            ),
            evidence={"ingress": ingress or "all"},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class CloudRunPublicInvokerRule(PolicyRule):
    """GCP-CR-002: Flag Cloud Run services invokable by allUsers."""

    rule_id: str = "GCP-CR-002"
    rule_name: str = "Cloud Run service publicly invokable"
    resource_types: list[str] = ["google.run.Service"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_AC-3", "ISO_27001_A.5.15"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``invoker_members`` contains a public member."""
        members = {str(m) for m in (snapshot.config.get("invoker_members") or [])}
        public = members & {"allUsers", "allAuthenticatedUsers"}
        if not public:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Cloud Run service '{snapshot.resource_name}' can be "
                f"invoked by {', '.join(sorted(public))}."
            ),
            evidence={"public_invokers": sorted(public)},
            compliance_frameworks=list(self.compliance_frameworks),
        )
