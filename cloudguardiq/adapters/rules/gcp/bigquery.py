"""CloudGuardIQ -- GCP BigQuery security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

_PUBLIC_MEMBERS: set[str] = {"allUsers", "allAuthenticatedUsers"}


class BigQueryDatasetPublicAccessRule(PolicyRule):
    """GCP-BQ-001: Flag BigQuery datasets granting access to allUsers."""

    rule_id: str = "GCP-BQ-001"
    rule_name: str = "BigQuery dataset is publicly accessible"
    resource_types: list[str] = ["google.bigquery.Dataset"]
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_7.1",
        "NIST_AC-3",
        "ISO_27001_A.5.10",
        "PCI_DSS_7.1.2",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when any access entry grants a public member."""
        access_entries = snapshot.config.get("access") or []
        public_grants = [
            entry
            for entry in access_entries
            if str(entry.get("specialGroup") or entry.get("iamMember") or "")
            in _PUBLIC_MEMBERS
            or str(entry.get("userByEmail") or "") in _PUBLIC_MEMBERS
        ]
        if not public_grants:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"BigQuery dataset '{snapshot.resource_name}' grants access "
                "to allUsers or allAuthenticatedUsers."
            ),
            evidence={"public_grants": public_grants},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class BigQueryDatasetCmekRule(PolicyRule):
    """GCP-BQ-002: Flag BigQuery datasets without a CMEK default key."""

    rule_id: str = "GCP-BQ-002"
    rule_name: str = "BigQuery dataset not CMEK-encrypted"
    resource_types: list[str] = ["google.bigquery.Dataset"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_7.2",
        "NIST_SC-28",
        "ISO_27001_A.8.24",
        "HIPAA_164.312(a)(2)(iv)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``default_kms_key_name`` is unset."""
        if snapshot.config.get("default_kms_key_name"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"BigQuery dataset '{snapshot.resource_name}' uses the "
                "Google-managed key. CIS baselines recommend CMEK."
            ),
            evidence={"default_kms_key_name": None},
            compliance_frameworks=list(self.compliance_frameworks),
        )
