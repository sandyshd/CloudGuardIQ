"""CloudGuardIQ — AWS FinOps (waste detection) rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class UnattachedEipRule(PolicyRule):
    """AWS-FINOPS-001: Flag Elastic IPs that are not associated with any resource."""

    rule_id: str = "AWS-FINOPS-001"
    rule_name: str = "Elastic IP is unattached"
    resource_types: list[str] = ["AWS::EC2::EIP"]
    severity: Severity = Severity.LOW
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = ["FINOPS_BP_1.2"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when the EIP has no association id."""
        if snapshot.config.get("association_id"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Elastic IP '{snapshot.resource_name}' is allocated but "
                "not associated. AWS bills unattached EIPs hourly."
            ),
            evidence={
                "public_ip": snapshot.config.get("public_ip"),
                "association_id": None,
            },
            waste_monthly_usd=float(snapshot.cost_monthly),
            compliance_frameworks=list(self.compliance_frameworks),
        )
