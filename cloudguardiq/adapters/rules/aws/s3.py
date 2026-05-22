"""CloudGuardIQ — AWS S3 bucket security rules.

Rules read only from ``ResourceSnapshot.config`` populated by
``AWSAdapter`` from boto3 responses. They never import boto3.
"""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


def _public_acl_grants(config: dict) -> list[str]:
    """Return URIs from ACL grants that target the public groups."""
    acl = config.get("acl") or {}
    grants = acl.get("Grants") or []
    public_uris = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
    public: list[str] = []
    for grant in grants:
        grantee = grant.get("Grantee") or {}
        uri = grantee.get("URI")
        if uri in public_uris:
            public.append(uri)
    return public


class S3PublicAclRule(PolicyRule):
    """AWS-S3-001: Flag S3 buckets with a public ACL grant."""

    rule_id: str = "AWS-S3-001"
    rule_name: str = "S3 bucket ACL grants public access"
    resource_types: list[str] = ["AWS::S3::Bucket"]
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_2.1.5",
        "NIST_AC-3",
        "SOC2_CC6.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when any ACL grant targets the public groups."""
        public = _public_acl_grants(snapshot.config)
        if not public:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"S3 bucket '{snapshot.resource_name}' has an ACL grant "
                "that targets a public group."
            ),
            evidence={"public_grantees": public},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class S3PublicAccessBlockRule(PolicyRule):
    """AWS-S3-002: Flag S3 buckets without full Public Access Block."""

    rule_id: str = "AWS-S3-002"
    rule_name: str = "S3 bucket Public Access Block not fully enabled"
    resource_types: list[str] = ["AWS::S3::Bucket"]
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["CIS_AWS_2.1.5", "NIST_AC-3"]

    REQUIRED_KEYS = (
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    )

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when any Public Access Block setting is off."""
        block = snapshot.config.get("public_access_block") or {}
        missing = [k for k in self.REQUIRED_KEYS if block.get(k) is not True]
        if not missing:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"S3 bucket '{snapshot.resource_name}' is missing one or "
                f"more Public Access Block settings: {', '.join(missing)}."
            ),
            evidence={"missing_settings": missing},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class S3BucketEncryptionRule(PolicyRule):
    """AWS-S3-003: Flag S3 buckets without default server-side encryption."""

    rule_id: str = "AWS-S3-003"
    rule_name: str = "S3 bucket missing default encryption"
    resource_types: list[str] = ["AWS::S3::Bucket"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_AWS_2.1.1",
        "NIST_SC-28",
        "SOC2_CC6.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when bucket has no default encryption configured."""
        encryption = snapshot.config.get("encryption") or {}
        rules = encryption.get("Rules") or []
        if rules:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"S3 bucket '{snapshot.resource_name}' does not have a "
                "default server-side encryption configuration."
            ),
            evidence={"encryption_rules": rules},
            compliance_frameworks=list(self.compliance_frameworks),
        )
