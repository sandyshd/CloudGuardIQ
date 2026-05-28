"""CloudGuardIQ -- GCP data services (Spanner, Memorystore, BigQuery extras)."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class SpannerCmekRule(PolicyRule):
    """GCP-SPN-001: Flag Spanner databases without CMEK."""

    rule_id: str = "GCP-SPN-001"
    rule_name: str = "Spanner database not CMEK-encrypted"
    resource_types: list[str] = ["google.spanner.Database"]
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
                f"Spanner database '{snapshot.resource_name}' uses the "
                "Google-managed key."
            ),
            evidence={"kms_key_name": None},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class MemorystoreAuthDisabledRule(PolicyRule):
    """GCP-MEM-001: Flag Memorystore for Redis instances without AUTH."""

    rule_id: str = "GCP-MEM-001"
    rule_name: str = "Memorystore Redis AUTH disabled"
    resource_types: list[str] = ["google.redis.Instance"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_IA-2", "PCI_DSS_8.3"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``auth_enabled`` is False."""
        if snapshot.config.get("auth_enabled") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Memorystore Redis instance '{snapshot.resource_name}' "
                "does not require AUTH for connections."
            ),
            evidence={
                "auth_enabled": snapshot.config.get("auth_enabled", False),
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )


class MemorystoreTransitEncryptionRule(PolicyRule):
    """GCP-MEM-002: Flag Memorystore for Redis instances without in-transit encryption."""

    rule_id: str = "GCP-MEM-002"
    rule_name: str = "Memorystore Redis in-transit encryption disabled"
    resource_types: list[str] = ["google.redis.Instance"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = ["NIST_SC-8", "PCI_DSS_4.1"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when transit_encryption_mode is DISABLED."""
        mode = str(snapshot.config.get("transit_encryption_mode", "")).upper()
        if mode == "SERVER_AUTHENTICATION":
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"Memorystore Redis instance '{snapshot.resource_name}' "
                "does not encrypt traffic in transit."
            ),
            evidence={"transit_encryption_mode": mode or "DISABLED"},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class BigQueryTablePartitionExpiryRule(PolicyRule):
    """GCP-BQ-003: Flag partitioned BigQuery tables without expiry (FinOps)."""

    rule_id: str = "GCP-BQ-003"
    rule_name: str = "BigQuery partitioned table has no expiry"
    resource_types: list[str] = ["google.bigquery.Table"]
    severity: Severity = Severity.LOW
    finding_type: FindingType = FindingType.FINOPS
    compliance_frameworks: list[str] = ["FINOPS_BP_2.1"]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when partitioning is set but expiration is empty."""
        partitioning = snapshot.config.get("time_partitioning") or {}
        if not partitioning:
            return None
        if partitioning.get("expiration_ms"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"BigQuery table '{snapshot.resource_name}' is partitioned "
                "but has no partition expiration; storage will grow forever."
            ),
            evidence={"time_partitioning": partitioning},
            waste_monthly_usd=float(snapshot.cost_monthly),
            compliance_frameworks=list(self.compliance_frameworks),
        )
