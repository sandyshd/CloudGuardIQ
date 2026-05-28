"""Pass/fail tests for new GCP rules (Cloud SQL, GKE, BigQuery, Logging)."""

from __future__ import annotations

from typing import Any

from cloudguardiq.adapters.rules.gcp.bigquery import (
    BigQueryDatasetCmekRule,
    BigQueryDatasetPublicAccessRule,
)
from cloudguardiq.adapters.rules.gcp.cloudsql import (
    CloudSqlBackupDisabledRule,
    CloudSqlPublicIpRule,
    CloudSqlRequireSslRule,
)
from cloudguardiq.adapters.rules.gcp.gke import (
    GkeLoggingDisabledRule,
    GkeNetworkPolicyRule,
    GkePrivateClusterRule,
)
from cloudguardiq.adapters.rules.gcp.logging import (
    LoggingRetentionRule,
    LoggingSinkMissingRule,
)
from cloudguardiq.core.enums import CloudProvider, DataTier, Severity
from cloudguardiq.core.models import ResourceSnapshot


def _snap(resource_type: str, config: dict[str, Any], name: str = "r1") -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id="proj-123",
        resource_group="gcp-global",
        resource_type=resource_type,
        resource_name=name,
        region="us-central1",
        provider=CloudProvider.GCP,
        data_tier=DataTier.TIER1_NATIVE,
        config=config,
    )


# ---------------------------------------------------------------------------
# Cloud SQL
# ---------------------------------------------------------------------------


class TestCloudSqlPublicIp:
    def test_fail_when_public(self) -> None:
        snap = _snap("google.sql.Instance", {"ipv4_enabled": True})
        result = CloudSqlPublicIpRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "GCP-SQL-001"
        assert result.severity is Severity.HIGH

    def test_pass_when_private(self) -> None:
        snap = _snap("google.sql.Instance", {"ipv4_enabled": False})
        assert CloudSqlPublicIpRule().evaluate(snap) is None


class TestCloudSqlBackupDisabled:
    def test_fail_when_disabled(self) -> None:
        snap = _snap("google.sql.Instance", {"backup_enabled": False})
        result = CloudSqlBackupDisabledRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "GCP-SQL-002"

    def test_pass_when_enabled(self) -> None:
        snap = _snap("google.sql.Instance", {"backup_enabled": True})
        assert CloudSqlBackupDisabledRule().evaluate(snap) is None


class TestCloudSqlRequireSsl:
    def test_fail_when_not_required(self) -> None:
        snap = _snap("google.sql.Instance", {"require_ssl": False})
        result = CloudSqlRequireSslRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "GCP-SQL-003"

    def test_pass_when_required(self) -> None:
        snap = _snap("google.sql.Instance", {"require_ssl": True})
        assert CloudSqlRequireSslRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# GKE
# ---------------------------------------------------------------------------


class TestGkePrivateCluster:
    def test_fail_when_not_private(self) -> None:
        snap = _snap("google.container.Cluster", {"enable_private_nodes": False})
        result = GkePrivateClusterRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "GCP-GKE-001"

    def test_pass_when_private(self) -> None:
        snap = _snap("google.container.Cluster", {"enable_private_nodes": True})
        assert GkePrivateClusterRule().evaluate(snap) is None


class TestGkeLoggingDisabled:
    def test_fail_when_none(self) -> None:
        snap = _snap("google.container.Cluster", {"logging_service": "none"})
        result = GkeLoggingDisabledRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "GCP-GKE-002"

    def test_pass_when_logging_enabled(self) -> None:
        snap = _snap(
            "google.container.Cluster",
            {"logging_service": "logging.googleapis.com/kubernetes"},
        )
        assert GkeLoggingDisabledRule().evaluate(snap) is None


class TestGkeNetworkPolicy:
    def test_fail_when_disabled(self) -> None:
        snap = _snap(
            "google.container.Cluster", {"network_policy_enabled": False}
        )
        result = GkeNetworkPolicyRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "GCP-GKE-003"

    def test_pass_when_enabled(self) -> None:
        snap = _snap(
            "google.container.Cluster", {"network_policy_enabled": True}
        )
        assert GkeNetworkPolicyRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# BigQuery
# ---------------------------------------------------------------------------


class TestBigQueryDatasetPublicAccess:
    def test_fail_when_all_users(self) -> None:
        snap = _snap(
            "google.bigquery.Dataset",
            {"access": [{"specialGroup": "allUsers", "role": "READER"}]},
        )
        result = BigQueryDatasetPublicAccessRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "GCP-BQ-001"
        assert result.severity is Severity.CRITICAL

    def test_pass_when_private(self) -> None:
        snap = _snap(
            "google.bigquery.Dataset",
            {"access": [{"userByEmail": "owner@example.com", "role": "OWNER"}]},
        )
        assert BigQueryDatasetPublicAccessRule().evaluate(snap) is None


class TestBigQueryDatasetCmek:
    def test_fail_when_no_cmek(self) -> None:
        snap = _snap("google.bigquery.Dataset", {})
        result = BigQueryDatasetCmekRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "GCP-BQ-002"

    def test_pass_when_cmek_set(self) -> None:
        snap = _snap(
            "google.bigquery.Dataset",
            {
                "default_kms_key_name": (
                    "projects/p/locations/us/keyRings/r/cryptoKeys/k"
                )
            },
        )
        assert BigQueryDatasetCmekRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# Cloud Logging
# ---------------------------------------------------------------------------


class TestLoggingSinkMissing:
    def test_fail_when_no_catchall_sink(self) -> None:
        snap = _snap(
            "google.logging.Project",
            {"sinks": [{"name": "sec", "filter": "severity>=ERROR"}]},
        )
        result = LoggingSinkMissingRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "GCP-LOG-001"

    def test_pass_when_catchall(self) -> None:
        snap = _snap(
            "google.logging.Project",
            {"sinks": [{"name": "all", "filter": ""}]},
        )
        assert LoggingSinkMissingRule().evaluate(snap) is None


class TestLoggingRetention:
    def test_fail_when_below_365(self) -> None:
        snap = _snap("google.logging.LogBucket", {"retention_days": 30})
        result = LoggingRetentionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "GCP-LOG-002"

    def test_pass_when_365(self) -> None:
        snap = _snap("google.logging.LogBucket", {"retention_days": 400})
        assert LoggingRetentionRule().evaluate(snap) is None
