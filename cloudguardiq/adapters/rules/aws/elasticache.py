"""CloudGuardIQ — AWS ElastiCache rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class ElastiCacheAtRestEncryptionRule(PolicyRule):
    """AWS-EC-001: Flag ElastiCache replication groups without at-rest encryption."""

    rule_id: str = "AWS-EC-001"
    rule_name: str = "ElastiCache at-rest encryption disabled"
    resource_types: list[str] = ["AWS::ElastiCache::ReplicationGroup"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SC-28", "PCI_DSS_3.5.1"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``at_rest_encryption_enabled`` is False."""
        if snapshot.config.get("at_rest_encryption_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"ElastiCache replication group '{snapshot.resource_name}' "
                "does not encrypt data at rest."
            ),
            evidence={
                "at_rest_encryption_enabled": snapshot.config.get(
                    "at_rest_encryption_enabled", False
                ),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class ElastiCacheTransitEncryptionRule(PolicyRule):
    """AWS-EC-002: Flag ElastiCache replication groups without in-transit encryption."""

    rule_id: str = "AWS-EC-002"
    rule_name: str = "ElastiCache in-transit encryption disabled"
    resource_types: list[str] = ["AWS::ElastiCache::ReplicationGroup"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SC-8", "PCI_DSS_4.1"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``transit_encryption_enabled`` is False."""
        if snapshot.config.get("transit_encryption_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"ElastiCache replication group '{snapshot.resource_name}' "
                "does not encrypt data in transit."
            ),
            evidence={
                "transit_encryption_enabled": snapshot.config.get(
                    "transit_encryption_enabled", False
                ),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )
