"""CloudGuardIQ -- GCP Compute extras (shielded VM, OS Login, default SA)."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class InstanceShieldedVmRule(PolicyRule):
    """GCP-CE-004: Flag Compute Engine VMs without all shielded VM features."""

    rule_id: str = "GCP-CE-004"
    rule_name: str = "Compute Engine shielded VM features incomplete"
    resource_types: list[str] = ["google.compute.Instance"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_4.8",
        "NIST_SI-7",
        "ISO_27001_A.8.9",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when any shielded VM property is False."""
        cfg = snapshot.config.get("shielded_instance_config") or {}
        missing = sorted(
            key
            for key in ("enable_secure_boot", "enable_vtpm", "enable_integrity_monitoring")
            if not cfg.get(key)
        )
        if not missing:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Compute Engine instance '{snapshot.resource_name}' is "
                f"missing shielded VM features: {', '.join(missing)}."
            ),
            evidence={"missing_features": missing},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class InstanceOsLoginDisabledRule(PolicyRule):
    """GCP-CE-005: Flag Compute Engine VMs with OS Login disabled."""

    rule_id: str = "GCP-CE-005"
    rule_name: str = "Compute Engine OS Login disabled"
    resource_types: list[str] = ["google.compute.Instance"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["CIS_GCP_4.4", "NIST_AC-3"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when OS Login metadata is not TRUE."""
        value = str(snapshot.config.get("enable_oslogin", "")).upper()
        if value == "TRUE":
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Compute Engine instance '{snapshot.resource_name}' does "
                "not enforce OS Login for SSH access."
            ),
            evidence={"enable_oslogin": value or "FALSE"},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class InstanceDefaultServiceAccountRule(PolicyRule):
    """GCP-CE-006: Flag Compute Engine VMs using the default service account."""

    rule_id: str = "GCP-CE-006"
    rule_name: str = "Compute Engine uses default service account"
    resource_types: list[str] = ["google.compute.Instance"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["CIS_GCP_4.1", "NIST_AC-6"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``service_account_email`` looks default."""
        emails = snapshot.config.get("service_account_emails") or []
        default = [
            email
            for email in emails
            if email.endswith("-compute@developer.gserviceaccount.com")
        ]
        if not default:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Compute Engine instance '{snapshot.resource_name}' is "
                "attached to the default Compute Engine service account."
            ),
            evidence={"default_service_accounts": default},
            compliance_frameworks=list(self.compliance_frameworks),
        )
