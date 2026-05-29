"""CloudGuardIQ — AWS DynamoDB rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class DynamoDbCmekEncryptionRule(PolicyRule):
    """AWS-DDB-001: Flag DynamoDB tables not encrypted with a CMK."""

    rule_id: str = "AWS-DDB-001"
    rule_name: str = "DynamoDB table not encrypted with CMK"
    resource_types: list[str] = ["AWS::DynamoDB::Table"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SC-28", "ISO_27001_A.8.24"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when SSE type is not KMS or no KMS key is set."""
        sse = snapshot.config.get("sse_description") or {}
        sse_type = str(sse.get("SSEType") or "").upper()
        key_arn = sse.get("KMSMasterKeyArn") or ""
        if sse_type == "KMS" and key_arn:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"DynamoDB table '{snapshot.resource_name}' is not "
                "encrypted with a customer-managed KMS key."
            ),
            evidence={"sse_type": sse_type, "kms_key_arn": key_arn},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class DynamoDbPitrDisabledRule(PolicyRule):
    """AWS-DDB-002: Flag DynamoDB tables without point-in-time recovery."""

    rule_id: str = "AWS-DDB-002"
    rule_name: str = "DynamoDB point-in-time recovery disabled"
    resource_types: list[str] = ["AWS::DynamoDB::Table"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = ["NIST_CP-9", "ISO_27001_A.8.13"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``pitr_enabled`` is False."""
        if snapshot.config.get("pitr_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"DynamoDB table '{snapshot.resource_name}' does not have "
                "point-in-time recovery enabled."
            ),
            evidence={"pitr_enabled": snapshot.config.get("pitr_enabled", False)},
            compliance_frameworks=list(self.compliance_frameworks),
        )
