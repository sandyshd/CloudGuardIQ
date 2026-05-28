"""CloudGuardIQ — AWS SNS / SQS rules."""

from __future__ import annotations

import json
from typing import Any

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


def _policy_allows_anonymous(policy: Any) -> bool:
    """Return True when an IAM resource policy grants ``Principal: *``."""
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except (TypeError, ValueError):
            return False
    if not isinstance(policy, dict):
        return False
    for stmt in policy.get("Statement") or []:
        if not isinstance(stmt, dict):
            continue
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        principal = stmt.get("Principal")
        if principal == "*" or principal == {"AWS": "*"}:
            return True
        if isinstance(principal, dict):
            aws = principal.get("AWS")
            if aws == "*" or (isinstance(aws, list) and "*" in aws):
                return True
    return False


class SnsTopicEncryptionRule(PolicyRule):
    """AWS-SNS-001: Flag SNS topics without server-side encryption."""

    rule_id: str = "AWS-SNS-001"
    rule_name: str = "SNS topic not encrypted at rest"
    resource_types: list[str] = ["AWS::SNS::Topic"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SC-28", "ISO_27001_A.8.24"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``kms_master_key_id`` is empty."""
        key = snapshot.config.get("kms_master_key_id") or ""
        if key:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"SNS topic '{snapshot.resource_name}' has no KMS key "
                "configured for at-rest encryption."
            ),
            evidence={"kms_master_key_id": key},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class SnsTopicPublicAccessRule(PolicyRule):
    """AWS-SNS-002: Flag SNS topics with an anonymous (Principal=*) policy."""

    rule_id: str = "AWS-SNS-002"
    rule_name: str = "SNS topic policy allows anonymous principals"
    resource_types: list[str] = ["AWS::SNS::Topic"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_AC-3", "ISO_27001_A.5.15"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when the topic policy allows Principal=*."""
        if not _policy_allows_anonymous(snapshot.config.get("policy")):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"SNS topic '{snapshot.resource_name}' policy grants access "
                "to any AWS principal."
            ),
            evidence={"policy": snapshot.config.get("policy")},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class SqsQueueEncryptionRule(PolicyRule):
    """AWS-SQS-001: Flag SQS queues without server-side encryption."""

    rule_id: str = "AWS-SQS-001"
    rule_name: str = "SQS queue not encrypted at rest"
    resource_types: list[str] = ["AWS::SQS::Queue"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SC-28", "ISO_27001_A.8.24"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when neither SSE-SQS nor a KMS key is set."""
        kms_key = snapshot.config.get("kms_master_key_id") or ""
        sqs_managed = bool(snapshot.config.get("sqs_managed_sse_enabled"))
        if kms_key or sqs_managed:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"SQS queue '{snapshot.resource_name}' is not configured "
                "with server-side encryption."
            ),
            evidence={
                "kms_master_key_id": kms_key,
                "sqs_managed_sse_enabled": sqs_managed,
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class SqsQueuePublicAccessRule(PolicyRule):
    """AWS-SQS-002: Flag SQS queues whose policy allows anonymous principals."""

    rule_id: str = "AWS-SQS-002"
    rule_name: str = "SQS queue policy allows anonymous principals"
    resource_types: list[str] = ["AWS::SQS::Queue"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_AC-3", "ISO_27001_A.5.15"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when the queue policy allows Principal=*."""
        if not _policy_allows_anonymous(snapshot.config.get("policy")):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"SQS queue '{snapshot.resource_name}' policy grants access "
                "to any AWS principal."
            ),
            evidence={"policy": snapshot.config.get("policy")},
            compliance_frameworks=list(self.compliance_frameworks),
        )
