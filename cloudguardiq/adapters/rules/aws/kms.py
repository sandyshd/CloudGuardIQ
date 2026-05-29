"""CloudGuardIQ — AWS KMS rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class KmsKeyRotationRule(PolicyRule):
    """AWS-KMS-001: Flag customer-managed KMS keys without annual rotation."""

    rule_id: str = "AWS-KMS-001"
    rule_name: str = "KMS customer-managed key rotation disabled"
    resource_types: list[str] = ["AWS::KMS::Key"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_3.0_3.8",
        "NIST_SC-12",
        "PCI_DSS_3.6.4",
        "ISO_27001_A.8.24",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding for CMKs (origin AWS_KMS) without rotation enabled."""
        manager = str(snapshot.config.get("key_manager", "")).upper()
        if manager and manager != "CUSTOMER":
            return None
        origin = str(snapshot.config.get("origin", "AWS_KMS")).upper()
        if origin != "AWS_KMS":
            return None
        if snapshot.config.get("key_rotation_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"KMS key '{snapshot.resource_name}' does not have annual "
                "automatic key rotation enabled."
            ),
            evidence={
                "key_rotation_enabled": snapshot.config.get(
                    "key_rotation_enabled", False
                ),
                "origin": origin,
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )
