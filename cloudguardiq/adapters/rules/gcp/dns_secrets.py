"""CloudGuardIQ -- GCP Cloud DNS / Secret Manager / Artifact Registry rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class DnsDnssecDisabledRule(PolicyRule):
    """GCP-DNS-001: Flag public managed DNS zones without DNSSEC."""

    rule_id: str = "GCP-DNS-001"
    rule_name: str = "Cloud DNS zone has DNSSEC disabled"
    resource_types: list[str] = ["google.dns.ManagedZone"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["CIS_GCP_3.3", "NIST_SC-20"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when zone is public and DNSSEC is not ON."""
        visibility = str(snapshot.config.get("visibility", "public")).lower()
        if visibility != "public":
            return None
        state = str(snapshot.config.get("dnssec_state", "")).lower()
        if state == "on":
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Public DNS zone '{snapshot.resource_name}' has DNSSEC "
                f"state '{state or 'off'}'."
            ),
            evidence={"dnssec_state": state or "off"},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class SecretManagerCmekRule(PolicyRule):
    """GCP-SEC-001: Flag Secret Manager secrets that do not use a CMEK."""

    rule_id: str = "GCP-SEC-001"
    rule_name: str = "Secret Manager secret not CMEK-encrypted"
    resource_types: list[str] = ["google.secretmanager.Secret"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SC-28", "ISO_27001_A.8.24"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when no ``customer_managed_kms_key`` is configured."""
        if snapshot.config.get("customer_managed_kms_key"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Secret '{snapshot.resource_name}' is encrypted with the "
                "Google-managed key. Enterprise baselines require CMEK."
            ),
            evidence={"customer_managed_kms_key": None},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class ArtifactRegistryCmekRule(PolicyRule):
    """GCP-AR-001: Flag Artifact Registry repositories without CMEK."""

    rule_id: str = "GCP-AR-001"
    rule_name: str = "Artifact Registry repository not CMEK-encrypted"
    resource_types: list[str] = ["google.artifactregistry.Repository"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SC-28", "ISO_27001_A.8.24"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``kms_key_name`` is missing."""
        if snapshot.config.get("kms_key_name"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Artifact Registry repository '{snapshot.resource_name}' "
                "uses the Google-managed key."
            ),
            evidence={"kms_key_name": None},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class ArtifactRegistryPublicAccessRule(PolicyRule):
    """GCP-AR-002: Flag Artifact Registry repositories accessible by allUsers."""

    rule_id: str = "GCP-AR-002"
    rule_name: str = "Artifact Registry repository publicly accessible"
    resource_types: list[str] = ["google.artifactregistry.Repository"]
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
                f"Artifact Registry repository '{snapshot.resource_name}' "
                f"grants access to {', '.join(public)}."
            ),
            evidence={"public_members": public},
            compliance_frameworks=list(self.compliance_frameworks),
        )
