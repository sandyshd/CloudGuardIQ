"""CloudGuardIQ — AWS EKS security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

_REQUIRED_LOG_TYPES: set[str] = {"api", "audit", "authenticator"}


class EksPublicEndpointRule(PolicyRule):
    """AWS-EKS-001: Flag EKS clusters whose API server is publicly reachable."""

    rule_id: str = "AWS-EKS-001"
    rule_name: str = "EKS API server publicly exposed"
    resource_types: list[str] = ["AWS::EKS::Cluster"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_EKS_5.4.1",
        "NIST_SC-7",
        "ISO_27001_A.8.20",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when public access is on with no IP allow-list."""
        public = bool(snapshot.config.get("endpoint_public_access"))
        if not public:
            return None
        cidrs = snapshot.config.get("public_access_cidrs") or []
        if cidrs and "0.0.0.0/0" not in cidrs:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"EKS cluster '{snapshot.resource_name}' API server is "
                "reachable from the public internet."
            ),
            evidence={
                "endpoint_public_access": True,
                "public_access_cidrs": list(cidrs),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class EksControlPlaneLoggingRule(PolicyRule):
    """AWS-EKS-002: Flag EKS clusters missing required control-plane logs."""

    rule_id: str = "AWS-EKS-002"
    rule_name: str = "EKS control plane logging incomplete"
    resource_types: list[str] = ["AWS::EKS::Cluster"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_EKS_2.1.1",
        "NIST_AU-2",
        "SOC2_CC7.2",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when required log types are not enabled."""
        enabled = {
            str(t).lower()
            for t in (snapshot.config.get("enabled_log_types") or [])
        }
        missing = sorted(_REQUIRED_LOG_TYPES - enabled)
        if not missing:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"EKS cluster '{snapshot.resource_name}' is missing control "
                f"plane log types: {', '.join(missing)}."
            ),
            evidence={
                "enabled_log_types": sorted(enabled),
                "missing_log_types": missing,
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class EksSecretsEncryptionRule(PolicyRule):
    """AWS-EKS-003: Flag EKS clusters without envelope encryption for secrets."""

    rule_id: str = "AWS-EKS-003"
    rule_name: str = "EKS Kubernetes secrets not envelope-encrypted"
    resource_types: list[str] = ["AWS::EKS::Cluster"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_EKS_5.3.1",
        "NIST_SC-28",
        "ISO_27001_A.8.24",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``secrets_kms_key_arn`` is missing."""
        if snapshot.config.get("secrets_kms_key_arn"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"EKS cluster '{snapshot.resource_name}' does not have "
                "envelope encryption (KMS) configured for Kubernetes secrets."
            ),
            evidence={"secrets_kms_key_arn": None},
            compliance_frameworks=list(self.compliance_frameworks),
        )
