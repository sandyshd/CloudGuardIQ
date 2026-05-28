"""Pass/fail tests for new Azure rules (SQL, AppService, AKS, Monitor)."""

from __future__ import annotations

from typing import Any

from cloudguardiq.adapters.rules.azure.aks import (
    AKSNetworkPolicyMissingRule,
    AKSPublicApiServerRule,
    AKSRBACDisabledRule,
)
from cloudguardiq.adapters.rules.azure.appservice import (
    AppServiceAuthDisabledRule,
    AppServiceHttpsOnlyRule,
    AppServiceMinTlsRule,
)
from cloudguardiq.adapters.rules.azure.monitor import (
    ActivityLogAlertsMissingRule,
    LogProfileRetentionRule,
)
from cloudguardiq.adapters.rules.azure.sql import (
    SqlAuditingDisabledRule,
    SqlMinTlsVersionRule,
    SqlPublicNetworkAccessRule,
)
from cloudguardiq.core.enums import CloudProvider, DataTier, Severity
from cloudguardiq.core.models import ResourceSnapshot


def _snap(resource_type: str, config: dict[str, Any], name: str = "r1") -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id="sub-test",
        resource_group="rg-test",
        resource_type=resource_type,
        resource_name=name,
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config=config,
    )


# ---------------------------------------------------------------------------
# SQL-001 / SQL-002 / SQL-003
# ---------------------------------------------------------------------------


class TestSqlPublicNetworkAccess:
    def test_fail_when_enabled(self) -> None:
        snap = _snap("Microsoft.Sql/servers", {"public_network_access": "Enabled"})
        result = SqlPublicNetworkAccessRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "SQL-001"
        assert result.severity is Severity.HIGH

    def test_pass_when_disabled(self) -> None:
        snap = _snap("Microsoft.Sql/servers", {"public_network_access": "Disabled"})
        assert SqlPublicNetworkAccessRule().evaluate(snap) is None


class TestSqlMinTlsVersion:
    def test_fail_when_below_12(self) -> None:
        snap = _snap("Microsoft.Sql/servers", {"minimal_tls_version": "1.0"})
        result = SqlMinTlsVersionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "SQL-002"

    def test_pass_when_12(self) -> None:
        snap = _snap("Microsoft.Sql/servers", {"minimal_tls_version": "1.2"})
        assert SqlMinTlsVersionRule().evaluate(snap) is None


class TestSqlAuditingDisabled:
    def test_fail_when_disabled(self) -> None:
        snap = _snap("Microsoft.Sql/servers", {"auditing_state": "Disabled"})
        result = SqlAuditingDisabledRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "SQL-003"

    def test_pass_when_enabled(self) -> None:
        snap = _snap("Microsoft.Sql/servers", {"auditing_state": "Enabled"})
        assert SqlAuditingDisabledRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# APP-001 / APP-002 / APP-003
# ---------------------------------------------------------------------------


class TestAppServiceHttpsOnly:
    def test_fail_when_https_only_false(self) -> None:
        snap = _snap("Microsoft.Web/sites", {"https_only": False})
        result = AppServiceHttpsOnlyRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "APP-001"

    def test_pass_when_https_only_true(self) -> None:
        snap = _snap("Microsoft.Web/sites", {"https_only": True})
        assert AppServiceHttpsOnlyRule().evaluate(snap) is None


class TestAppServiceMinTls:
    def test_fail_when_below_12(self) -> None:
        snap = _snap("Microsoft.Web/sites", {"min_tls_version": "1.0"})
        result = AppServiceMinTlsRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "APP-002"

    def test_pass_when_12(self) -> None:
        snap = _snap("Microsoft.Web/sites", {"min_tls_version": "1.2"})
        assert AppServiceMinTlsRule().evaluate(snap) is None


class TestAppServiceAuthDisabled:
    def test_fail_when_no_auth(self) -> None:
        snap = _snap("Microsoft.Web/sites", {"auth_enabled": False})
        result = AppServiceAuthDisabledRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "APP-003"

    def test_pass_when_easyauth(self) -> None:
        snap = _snap("Microsoft.Web/sites", {"auth_enabled": True})
        assert AppServiceAuthDisabledRule().evaluate(snap) is None

    def test_pass_when_client_cert(self) -> None:
        snap = _snap("Microsoft.Web/sites", {"client_cert_enabled": True})
        assert AppServiceAuthDisabledRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# AKS-001 / AKS-002 / AKS-003
# ---------------------------------------------------------------------------


class TestAKSRBACDisabled:
    def test_fail_when_rbac_off(self) -> None:
        snap = _snap(
            "Microsoft.ContainerService/managedClusters", {"enable_rbac": False}
        )
        result = AKSRBACDisabledRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AKS-001"

    def test_pass_when_rbac_on(self) -> None:
        snap = _snap(
            "Microsoft.ContainerService/managedClusters", {"enable_rbac": True}
        )
        assert AKSRBACDisabledRule().evaluate(snap) is None


class TestAKSPublicApiServer:
    def test_fail_when_public_and_no_ip_ranges(self) -> None:
        snap = _snap(
            "Microsoft.ContainerService/managedClusters",
            {"private_cluster": False, "authorized_ip_ranges": []},
        )
        result = AKSPublicApiServerRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AKS-002"

    def test_pass_when_private(self) -> None:
        snap = _snap(
            "Microsoft.ContainerService/managedClusters",
            {"private_cluster": True},
        )
        assert AKSPublicApiServerRule().evaluate(snap) is None

    def test_pass_when_authorized_ip_ranges(self) -> None:
        snap = _snap(
            "Microsoft.ContainerService/managedClusters",
            {"private_cluster": False, "authorized_ip_ranges": ["10.0.0.0/8"]},
        )
        assert AKSPublicApiServerRule().evaluate(snap) is None


class TestAKSNetworkPolicyMissing:
    def test_fail_when_none(self) -> None:
        snap = _snap(
            "Microsoft.ContainerService/managedClusters", {"network_policy": ""}
        )
        result = AKSNetworkPolicyMissingRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AKS-003"

    def test_pass_when_calico(self) -> None:
        snap = _snap(
            "Microsoft.ContainerService/managedClusters",
            {"network_policy": "calico"},
        )
        assert AKSNetworkPolicyMissingRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# MON-001 / MON-002
# ---------------------------------------------------------------------------


class TestActivityLogAlertsMissing:
    def test_fail_when_required_ops_missing(self) -> None:
        snap = _snap(
            "Microsoft.Insights/activityLogAlerts",
            {"monitored_operations": []},
        )
        result = ActivityLogAlertsMissingRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "MON-001"

    def test_pass_when_all_present(self) -> None:
        snap = _snap(
            "Microsoft.Insights/activityLogAlerts",
            {
                "monitored_operations": [
                    "Microsoft.Authorization/policyAssignments/write",
                    "Microsoft.Network/networkSecurityGroups/write",
                    "Microsoft.Sql/servers/firewallRules/write",
                    "Microsoft.KeyVault/vaults/write",
                ]
            },
        )
        assert ActivityLogAlertsMissingRule().evaluate(snap) is None


class TestLogProfileRetention:
    def test_fail_when_below_365(self) -> None:
        snap = _snap("Microsoft.Insights/logProfiles", {"retention_days": 90})
        result = LogProfileRetentionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "MON-002"

    def test_pass_when_365(self) -> None:
        snap = _snap("Microsoft.Insights/logProfiles", {"retention_days": 365})
        assert LogProfileRetentionRule().evaluate(snap) is None

    def test_pass_when_zero_means_forever(self) -> None:
        snap = _snap("Microsoft.Insights/logProfiles", {"retention_days": 0})
        assert LogProfileRetentionRule().evaluate(snap) is None
