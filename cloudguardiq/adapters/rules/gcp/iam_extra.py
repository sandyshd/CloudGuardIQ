"""CloudGuardIQ -- GCP IAM extras."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

_PRIMITIVE_ROLES: set[str] = {"roles/owner", "roles/editor", "roles/viewer"}
_PUBLIC_MEMBERS: set[str] = {"allUsers", "allAuthenticatedUsers"}


class IamPrimitiveRoleRule(PolicyRule):
    """GCP-IAM-002: Flag project IAM bindings that grant primitive roles."""

    rule_id: str = "GCP-IAM-002"
    rule_name: str = "Project uses primitive IAM roles"
    resource_types: list[str] = ["google.iam.ProjectPolicy"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_1.4",
        "NIST_AC-6",
        "ISO_27001_A.8.3",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when any binding uses a primitive role."""
        bindings = snapshot.config.get("bindings") or []
        primitive = [
            binding
            for binding in bindings
            if str(binding.get("role", "")) in _PRIMITIVE_ROLES
        ]
        if not primitive:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Project '{snapshot.resource_name}' uses "
                f"{len(primitive)} primitive role binding(s) "
                "(Owner/Editor/Viewer). Prefer predefined or custom roles."
            ),
            evidence={"primitive_bindings": primitive},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class IamPublicMemberRule(PolicyRule):
    """GCP-IAM-003: Flag project IAM bindings granted to allUsers."""

    rule_id: str = "GCP-IAM-003"
    rule_name: str = "Project IAM grants access to allUsers"
    resource_types: list[str] = ["google.iam.ProjectPolicy"]
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_GCP_1.1",
        "NIST_AC-3",
        "ISO_27001_A.5.15",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when any binding includes a public member."""
        bindings = snapshot.config.get("bindings") or []
        public_bindings = [
            binding
            for binding in bindings
            if any(
                member in _PUBLIC_MEMBERS for member in (binding.get("members") or [])
            )
        ]
        if not public_bindings:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Project '{snapshot.resource_name}' grants "
                f"{len(public_bindings)} role(s) to allUsers / "
                "allAuthenticatedUsers."
            ),
            evidence={"public_bindings": public_bindings},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class ServiceAccountKeyAgeRule(PolicyRule):
    """GCP-IAM-004: Flag service account keys older than 90 days."""

    rule_id: str = "GCP-IAM-004"
    rule_name: str = "Service account key older than 90 days"
    resource_types: list[str] = ["google.iam.ServiceAccount"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_GCP_1.7",
        "NIST_IA-5",
        "ISO_27001_A.5.16",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when any user-managed key has ``age_days`` > 90."""
        keys = snapshot.config.get("user_managed_keys") or []
        stale = [
            key for key in keys if int(key.get("age_days", 0) or 0) > 90
        ]
        if not stale:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Service account '{snapshot.resource_name}' has "
                f"{len(stale)} user-managed key(s) older than 90 days."
            ),
            evidence={"stale_keys": stale},
            compliance_frameworks=list(self.compliance_frameworks),
        )
