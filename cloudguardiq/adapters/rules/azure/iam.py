"""CloudGuardIQ — IAM security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingCategory, FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class OverprivilegedIdentityRule:
    """Check for identities with Owner role at subscription level."""

    rule_id: str = "IAM_OVERPRIVILEGED"
    resource_types: list[str] = ["Microsoft.Authorization/roleAssignments"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate for overprivileged role assignments."""
        findings: list[FindingResult] = []
        role_name = snapshot.properties.get("roleDefinitionName", "")
        scope = snapshot.properties.get("scope", "")
        if role_name == "Owner" and scope.count("/") <= 4:
            name = snapshot.resource_name
            findings.append(
                FindingResult(
                    snapshot_id=snapshot.id,
                    rule_id=self.rule_id,
                    title="Overprivileged identity with Owner role",
                    description=(
                        f"Role assignment '{name}' grants Owner "
                        "at subscription scope."
                    ),
                    severity=Severity.HIGH,
                    category=FindingCategory.SECURITY,
                    resource_id=snapshot.resource_id,
                    resource_type=snapshot.resource_type,
                    resource_name=name,
                    evidence={
                        "roleDefinitionName": role_name,
                        "scope": scope,
                    },
                    recommended_action=(
                        "Apply least-privilege: use Contributor "
                        "or a custom role."
                    ),
                )
            )
        return findings


# ---------------------------------------------------------------------------
# NativeScanner PolicyRule-based IAM rules (IAM-001 ... IAM-008)
# ---------------------------------------------------------------------------


class OwnerRoleDirectUserRule(PolicyRule):
    """IAM-001: Owner role assigned directly to a user (not managed identity/service principal)."""

    rule_id: str = "IAM-001"
    resource_types: list[str] = ["Microsoft.Authorization/roleAssignments"]
    rule_name: str = "Owner role assigned directly to a user"
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_1.1",
        "NIST_AC-6",
        "ISO_27001_A.5.18",
        "PCI_DSS_7.2.1",
        "HIPAA_164.308(a)(4)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if Owner role is assigned to a user principal."""
        role = snapshot.config.get("role_definition_name", "")
        principal_type = snapshot.config.get("principal_type", "")
        if role == "Owner" and principal_type == "User":
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Role assignment '{snapshot.resource_name}' grants Owner "
                    "role directly to a user instead of a managed identity or "
                    "service principal."
                ),
                evidence={
                    "role_definition_name": role,
                    "principal_type": principal_type,
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class OwnerRoleSubscriptionScopeRule(PolicyRule):
    """IAM-002: Owner role assigned at subscription root scope."""

    rule_id: str = "IAM-002"
    resource_types: list[str] = ["Microsoft.Authorization/roleAssignments"]
    rule_name: str = "Owner role at subscription root scope"
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_1.2",
        "ISO_27001_A.8.5",
        "PCI_DSS_8.4.2",
        "HIPAA_164.312(d)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if Owner is assigned at subscription root."""
        role = snapshot.config.get("role_definition_name", "")
        scope = snapshot.config.get("scope", "")
        if role == "Owner" and scope.startswith("/subscriptions/") and scope.count("/") <= 2:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Role assignment '{snapshot.resource_name}' grants Owner "
                    f"at subscription root scope '{scope}'."
                ),
                evidence={"role_definition_name": role, "scope": scope},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class SPOwnerMultipleSubscriptionsRule(PolicyRule):
    """IAM-003: Service principal has Owner role on multiple subscriptions."""

    rule_id: str = "IAM-003"
    resource_types: list[str] = ["Microsoft.Authorization/roleAssignments"]
    rule_name: str = "Service principal Owner on multiple subscriptions"
    severity: Severity = Severity.CRITICAL
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_1.3",
        "ISO_27001_A.8.5",
        "PCI_DSS_8.4.2",
        "HIPAA_164.312(d)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if SP has Owner on >1 subscription."""
        role = snapshot.config.get("role_definition_name", "")
        principal_type = snapshot.config.get("principal_type", "")
        owner_sub_count = snapshot.config.get("owner_subscription_count", 0)
        if role == "Owner" and principal_type == "ServicePrincipal" and owner_sub_count > 1:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Service principal '{snapshot.resource_name}' has Owner "
                    f"role on {owner_sub_count} subscriptions."
                ),
                evidence={
                    "principal_type": principal_type,
                    "owner_subscription_count": owner_sub_count,
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class GuestPrivilegedRoleRule(PolicyRule):
    """IAM-004: Guest user has privileged role (Contributor or higher)."""

    rule_id: str = "IAM-004"
    resource_types: list[str] = ["Microsoft.Authorization/roleAssignments"]
    rule_name: str = "Guest user with privileged role"
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_1.6",
        "ISO_27001_A.5.18",
        "PCI_DSS_7.2.4",
        "HIPAA_164.308(a)(4)",
    ]

    _privileged_roles: set[str] = {"Owner", "Contributor", "User Access Administrator"}

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if a guest user holds a privileged role."""
        role = snapshot.config.get("role_definition_name", "")
        principal_type = snapshot.config.get("principal_type", "")
        if principal_type == "Guest" and role in self._privileged_roles:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Guest user '{snapshot.resource_name}' has privileged "
                    f"role '{role}'."
                ),
                evidence={
                    "role_definition_name": role,
                    "principal_type": principal_type,
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class ClassicAdminRoleRule(PolicyRule):
    """IAM-005: Classic administrator roles still assigned."""

    rule_id: str = "IAM-005"
    resource_types: list[str] = ["Microsoft.Authorization/roleAssignments"]
    rule_name: str = "Classic administrator roles still assigned"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_1.7",
        "ISO_27001_A.5.18",
        "PCI_DSS_7.2.4",
        "HIPAA_164.308(a)(4)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if classic admin roles are in use."""
        if snapshot.config.get("is_classic_admin") is True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Classic administrator role is still assigned to "
                    f"'{snapshot.resource_name}'."
                ),
                evidence={"is_classic_admin": True},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class NoMFAConditionalAccessRule(PolicyRule):
    """IAM-006: No conditional access policy enforcing MFA evidence."""

    rule_id: str = "IAM-006"
    resource_types: list[str] = ["Microsoft.Authorization/roleAssignments"]
    rule_name: str = "No conditional access policy enforcing MFA"
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_1.5",
        "SOC2_CC6.1",
        "ISO_27001_A.8.2",
        "PCI_DSS_7.2.2",
        "HIPAA_164.312(a)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if MFA is not enforced via conditional access."""
        if snapshot.config.get("mfa_enforced") is not True:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Identity '{snapshot.resource_name}' has no conditional "
                    "access policy enforcing MFA."
                ),
                evidence={
                    "mfa_enforced": snapshot.config.get("mfa_enforced"),
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class ExternalUserPrivilegedRoleRule(PolicyRule):
    """IAM-007: External (B2B) user with Owner or Contributor role."""

    rule_id: str = "IAM-007"
    resource_types: list[str] = ["Microsoft.Authorization/roleAssignments"]
    rule_name: str = "External user with privileged role"
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_1.8",
        "ISO_27001_A.8.5",
        "PCI_DSS_8.3.6",
        "HIPAA_164.308(a)(5)(ii)(D)",
    ]

    _privileged_roles: set[str] = {"Owner", "Contributor"}

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if an external B2B user holds Owner or Contributor."""
        role = snapshot.config.get("role_definition_name", "")
        is_external = snapshot.config.get("is_external_user", False)
        if is_external and role in self._privileged_roles:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"External (B2B) user '{snapshot.resource_name}' has "
                    f"'{role}' role."
                ),
                evidence={
                    "role_definition_name": role,
                    "is_external_user": True,
                },
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None


class SPPasswordExpiryRule(PolicyRule):
    """IAM-008: Service principal password expiry not set (>365 days or never expires)."""

    rule_id: str = "IAM-008"
    resource_types: list[str] = ["Microsoft.Authorization/roleAssignments"]
    rule_name: str = "Service principal password expiry not set"
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_1.9",
        "ISO_27001_A.8.5",
        "PCI_DSS_8.3.6",
        "HIPAA_164.308(a)(5)(ii)(D)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding if SP credential expiry exceeds 365 days or is absent."""
        days = snapshot.config.get("credential_expiry_days")
        if days is None or days > 365:
            return FindingResult(
                resource_snapshot=snapshot,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                finding_type=self.finding_type,
                description=(
                    f"Service principal '{snapshot.resource_name}' has password "
                    f"expiry set to {days} days."
                    if days is not None
                    else (
                        f"Service principal '{snapshot.resource_name}' has no "
                        "password expiry configured."
                    )
                ),
                evidence={"credential_expiry_days": days},
                compliance_frameworks=list(self.compliance_frameworks),
            )
        return None
