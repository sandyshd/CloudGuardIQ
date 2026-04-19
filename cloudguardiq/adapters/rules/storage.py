"""CloudGuardIQ — Storage account security rules."""

from __future__ import annotations

from cloudguardiq.core.enums import FindingCategory, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class StorageHttpsOnlyRule:
    """Check that storage accounts enforce HTTPS-only traffic."""

    rule_id: str = "STORAGE_HTTPS_ONLY"
    resource_types: list[str] = ["Microsoft.Storage/storageAccounts"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate HTTPS enforcement on storage account."""
        findings: list[FindingResult] = []
        https_only = snapshot.properties.get("supportsHttpsTrafficOnly", True)
        if not https_only:
            name = snapshot.resource_name
            findings.append(
                FindingResult(
                    snapshot_id=snapshot.id,
                    rule_id=self.rule_id,
                    title="Storage account allows HTTP traffic",
                    description=(
                        f"Storage account '{name}' does not enforce HTTPS."
                    ),
                    severity=Severity.HIGH,
                    category=FindingCategory.SECURITY,
                    resource_id=snapshot.resource_id,
                    resource_type=snapshot.resource_type,
                    resource_name=name,
                    evidence={"supportsHttpsTrafficOnly": False},
                    recommended_action="Enable HTTPS-only on the storage account.",
                )
            )
        return findings


class StoragePublicAccessRule:
    """Check that storage accounts disable public blob access."""

    rule_id: str = "STORAGE_PUBLIC_ACCESS"
    resource_types: list[str] = ["Microsoft.Storage/storageAccounts"]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate public blob access settings."""
        findings: list[FindingResult] = []
        public_access = snapshot.properties.get("allowBlobPublicAccess", False)
        if public_access:
            name = snapshot.resource_name
            findings.append(
                FindingResult(
                    snapshot_id=snapshot.id,
                    rule_id=self.rule_id,
                    title="Storage account allows public blob access",
                    description=(
                        f"Storage account '{name}' allows public blob access."
                    ),
                    severity=Severity.CRITICAL,
                    category=FindingCategory.SECURITY,
                    resource_id=snapshot.resource_id,
                    resource_type=snapshot.resource_type,
                    resource_name=name,
                    evidence={"allowBlobPublicAccess": True},
                    recommended_action="Disable public blob access.",
                )
            )
        return findings
