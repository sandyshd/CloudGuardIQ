"""CloudGuardIQ — IAM security rules."""

from __future__ import annotations

from cloudguardiq.core.enums import FindingCategory, Severity
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
