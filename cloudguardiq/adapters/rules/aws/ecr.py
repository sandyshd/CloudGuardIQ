"""CloudGuardIQ — AWS ECR rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class EcrScanOnPushRule(PolicyRule):
    """AWS-ECR-001: Flag ECR repositories without scan-on-push enabled."""

    rule_id: str = "AWS-ECR-001"
    rule_name: str = "ECR repository scan-on-push disabled"
    resource_types: list[str] = ["AWS::ECR::Repository"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SI-2", "ISO_27001_A.8.8"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``scan_on_push`` is False."""
        if snapshot.config.get("scan_on_push") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"ECR repository '{snapshot.resource_name}' does not scan "
                "images automatically on push."
            ),
            evidence={
                "scan_on_push": snapshot.config.get("scan_on_push", False),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class EcrTagImmutabilityRule(PolicyRule):
    """AWS-ECR-002: Flag ECR repositories with mutable image tags."""

    rule_id: str = "AWS-ECR-002"
    rule_name: str = "ECR repository tags are mutable"
    resource_types: list[str] = ["AWS::ECR::Repository"]
    severity: Severity = Severity.LOW
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = ["NIST_CM-3", "ISO_27001_A.8.32"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when tag immutability is not enabled."""
        mode = str(snapshot.config.get("image_tag_mutability", "")).upper()
        if mode == "IMMUTABLE":
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"ECR repository '{snapshot.resource_name}' permits "
                "overwriting image tags — set tag mutability to IMMUTABLE."
            ),
            evidence={"image_tag_mutability": mode or "MUTABLE"},
            compliance_frameworks=list(self.compliance_frameworks),
        )
