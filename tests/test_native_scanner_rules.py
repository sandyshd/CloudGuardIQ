"""Tests for NativeScanner PolicyRule-based storage and network rules.

32 tests total — 2 per rule (pass case + fail case).
"""

from __future__ import annotations

from cloudguardiq.adapters.rules.azure.network import (
    AnyPortOpenToInternetRule,
    DDoSProtectionRule,
    InboundAllowAllRule,
    NSGFlowLogsRule,
    RDPOpenToInternetRule,
    SSHOpenToInternetRule,
)
from cloudguardiq.adapters.rules.azure.storage import (
    BlobSoftDeleteRule,
    BlobVersioningRule,
    DiagnosticLoggingRule,
    HttpTrafficAllowedRule,
    InfrastructureEncryptionRule,
    LifecycleManagementRule,
    MinTlsVersionRule,
    NetworkDefaultActionRule,
    PublicBlobAccessRule,
    SharedKeyAuthRule,
)
from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import ResourceSnapshot

# ---------------------------------------------------------------------------
# Helper: lightweight snapshot factory
# ---------------------------------------------------------------------------


def _storage_snap(
    config: dict | None = None,
    cost_monthly: float = 0.0,
) -> ResourceSnapshot:
    """Create a minimal storage-account snapshot with *config* overrides."""
    return ResourceSnapshot(
        subscription_id="sub-test",
        resource_group="rg-test",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="satest",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config=config or {},
        cost_monthly=cost_monthly,
    )


def _nsg_snap(config: dict | None = None) -> ResourceSnapshot:
    """Create a minimal NSG snapshot with *config* overrides."""
    return ResourceSnapshot(
        subscription_id="sub-test",
        resource_group="rg-test",
        resource_type="Microsoft.Network/networkSecurityGroups",
        resource_name="nsgtest",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config=config or {},
    )


def _vnet_snap(config: dict | None = None) -> ResourceSnapshot:
    """Create a minimal VNet snapshot with *config* overrides."""
    return ResourceSnapshot(
        subscription_id="sub-test",
        resource_group="rg-test",
        resource_type="Microsoft.Network/virtualNetworks",
        resource_name="vnettest",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config=config or {},
    )


# ===================================================================
# STORAGE RULES — 10 rules × 2 tests = 20 tests
# ===================================================================


class TestSTOR001PublicBlobAccess:
    """STOR-001: Public blob access enabled."""

    def test_fail_when_public_access_enabled(self) -> None:
        snap = _storage_snap({"allow_blob_public_access": True})
        result = PublicBlobAccessRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "STOR-001"
        assert result.severity == Severity.CRITICAL
        assert "CIS_3.1" in result.compliance_frameworks

    def test_pass_when_public_access_disabled(self) -> None:
        snap = _storage_snap({"allow_blob_public_access": False})
        assert PublicBlobAccessRule().evaluate(snap) is None


class TestSTOR002HttpTraffic:
    """STOR-002: HTTP traffic allowed (not HTTPS-only)."""

    def test_fail_when_https_not_enforced(self) -> None:
        snap = _storage_snap({"enable_https_traffic_only": False})
        result = HttpTrafficAllowedRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "STOR-002"
        assert result.severity == Severity.HIGH

    def test_pass_when_https_enforced(self) -> None:
        snap = _storage_snap({"enable_https_traffic_only": True})
        assert HttpTrafficAllowedRule().evaluate(snap) is None


class TestSTOR003MinTlsVersion:
    """STOR-003: Minimum TLS version below 1.2."""

    def test_fail_when_tls_1_0(self) -> None:
        snap = _storage_snap({"minimum_tls_version": "TLS1_0"})
        result = MinTlsVersionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "STOR-003"
        assert result.severity == Severity.HIGH

    def test_pass_when_tls_1_2(self) -> None:
        snap = _storage_snap({"minimum_tls_version": "TLS1_2"})
        assert MinTlsVersionRule().evaluate(snap) is None


class TestSTOR004SharedKeyAuth:
    """STOR-004: Shared key authentication enabled."""

    def test_fail_when_shared_key_allowed(self) -> None:
        snap = _storage_snap({"allow_shared_key_access": True})
        result = SharedKeyAuthRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "STOR-004"
        assert result.severity == Severity.MEDIUM

    def test_pass_when_shared_key_disabled(self) -> None:
        snap = _storage_snap({"allow_shared_key_access": False})
        assert SharedKeyAuthRule().evaluate(snap) is None


class TestSTOR005NetworkDefaultAction:
    """STOR-005: Network default action not Deny."""

    def test_scopes_to_storage_accounts_only(self) -> None:
        assert NetworkDefaultActionRule.resource_types == [
            "Microsoft.Storage/storageAccounts"
        ]

    def test_fail_when_default_allow(self) -> None:
        snap = _storage_snap({"network_default_action": "Allow"})
        result = NetworkDefaultActionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "STOR-005"
        assert result.severity == Severity.CRITICAL

    def test_pass_when_default_deny(self) -> None:
        snap = _storage_snap({"network_default_action": "Deny"})
        assert NetworkDefaultActionRule().evaluate(snap) is None


class TestSTOR006BlobSoftDelete:
    """STOR-006: Soft delete not enabled for blobs."""

    def test_fail_when_soft_delete_disabled(self) -> None:
        snap = _storage_snap({"blob_soft_delete_enabled": False})
        result = BlobSoftDeleteRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "STOR-006"
        assert result.severity == Severity.MEDIUM

    def test_pass_when_soft_delete_enabled(self) -> None:
        snap = _storage_snap({"blob_soft_delete_enabled": True})
        assert BlobSoftDeleteRule().evaluate(snap) is None


class TestSTOR007BlobVersioning:
    """STOR-007: Blob versioning not enabled."""

    def test_fail_when_versioning_disabled(self) -> None:
        snap = _storage_snap({"blob_versioning_enabled": False})
        result = BlobVersioningRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "STOR-007"
        assert result.severity == Severity.LOW

    def test_pass_when_versioning_enabled(self) -> None:
        snap = _storage_snap({"blob_versioning_enabled": True})
        assert BlobVersioningRule().evaluate(snap) is None


class TestSTOR008InfrastructureEncryption:
    """STOR-008: Infrastructure encryption not enabled."""

    def test_fail_when_infra_encryption_disabled(self) -> None:
        snap = _storage_snap({"infrastructure_encryption_enabled": False})
        result = InfrastructureEncryptionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "STOR-008"
        assert result.severity == Severity.MEDIUM

    def test_pass_when_infra_encryption_enabled(self) -> None:
        snap = _storage_snap({"infrastructure_encryption_enabled": True})
        assert InfrastructureEncryptionRule().evaluate(snap) is None


class TestSTOR009DiagnosticLogging:
    """STOR-009: No diagnostic logging configured."""

    def test_fail_when_logging_disabled(self) -> None:
        snap = _storage_snap({"diagnostic_logging_enabled": False})
        result = DiagnosticLoggingRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "STOR-009"
        assert result.severity == Severity.MEDIUM

    def test_pass_when_logging_enabled(self) -> None:
        snap = _storage_snap({"diagnostic_logging_enabled": True})
        assert DiagnosticLoggingRule().evaluate(snap) is None


class TestSTOR010LifecycleManagement:
    """STOR-010: No lifecycle management policy (FinOps)."""

    def test_fail_when_no_policy_and_high_cost(self) -> None:
        snap = _storage_snap(
            {"lifecycle_policy_exists": False}, cost_monthly=100.0
        )
        result = LifecycleManagementRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "STOR-010"
        assert result.finding_type == FindingType.FINOPS
        assert result.waste_monthly_usd == 35.0  # 100 * 0.35

    def test_pass_when_policy_exists(self) -> None:
        snap = _storage_snap(
            {"lifecycle_policy_exists": True}, cost_monthly=200.0
        )
        assert LifecycleManagementRule().evaluate(snap) is None


# ===================================================================
# NETWORK RULES — 6 rules × 2 tests = 12 tests
# ===================================================================


class TestNET001SSHOpen:
    """NET-001: SSH port 22 open to internet."""

    def test_fail_when_ssh_open(self) -> None:
        snap = _nsg_snap(
            {
                "securityRules": [
                    {
                        "destinationPortRange": "22",
                        "sourceAddressPrefix": "*",
                        "access": "Allow",
                        "direction": "Inbound",
                    }
                ]
            }
        )
        result = SSHOpenToInternetRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "NET-001"
        assert result.severity == Severity.CRITICAL

    def test_pass_when_ssh_restricted(self) -> None:
        snap = _nsg_snap(
            {
                "securityRules": [
                    {
                        "destinationPortRange": "22",
                        "sourceAddressPrefix": "10.0.0.0/8",
                        "access": "Allow",
                        "direction": "Inbound",
                    }
                ]
            }
        )
        assert SSHOpenToInternetRule().evaluate(snap) is None


class TestNET002RDPOpen:
    """NET-002: RDP port 3389 open to internet."""

    def test_fail_when_rdp_open(self) -> None:
        snap = _nsg_snap(
            {
                "securityRules": [
                    {
                        "destinationPortRange": "3389",
                        "sourceAddressPrefix": "0.0.0.0/0",
                        "access": "Allow",
                        "direction": "Inbound",
                    }
                ]
            }
        )
        result = RDPOpenToInternetRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "NET-002"
        assert result.severity == Severity.CRITICAL

    def test_pass_when_rdp_restricted(self) -> None:
        snap = _nsg_snap(
            {
                "securityRules": [
                    {
                        "destinationPortRange": "3389",
                        "sourceAddressPrefix": "10.0.0.0/8",
                        "access": "Allow",
                        "direction": "Inbound",
                    }
                ]
            }
        )
        assert RDPOpenToInternetRule().evaluate(snap) is None


class TestNET003AnyPortOpen:
    """NET-003: Any port open to internet (catch-all)."""

    def test_fail_when_all_ports_open(self) -> None:
        snap = _nsg_snap(
            {
                "securityRules": [
                    {
                        "destinationPortRange": "*",
                        "sourceAddressPrefix": "*",
                        "access": "Allow",
                        "direction": "Inbound",
                    }
                ]
            }
        )
        result = AnyPortOpenToInternetRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "NET-003"
        assert result.severity == Severity.HIGH

    def test_pass_when_specific_port_only(self) -> None:
        snap = _nsg_snap(
            {
                "securityRules": [
                    {
                        "destinationPortRange": "443",
                        "sourceAddressPrefix": "*",
                        "access": "Allow",
                        "direction": "Inbound",
                    }
                ]
            }
        )
        assert AnyPortOpenToInternetRule().evaluate(snap) is None


class TestNET004FlowLogs:
    """NET-004: NSG flow logs not enabled."""

    def test_fail_when_flow_logs_disabled(self) -> None:
        snap = _nsg_snap({"flow_logs_enabled": False})
        result = NSGFlowLogsRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "NET-004"
        assert result.severity == Severity.MEDIUM

    def test_pass_when_flow_logs_enabled(self) -> None:
        snap = _nsg_snap({"flow_logs_enabled": True})
        assert NSGFlowLogsRule().evaluate(snap) is None


class TestNET005InboundAllowAll:
    """NET-005: Inbound allow-all rule exists."""

    def test_fail_when_allow_all_exists(self) -> None:
        snap = _nsg_snap(
            {
                "securityRules": [
                    {
                        "destinationPortRange": "*",
                        "sourceAddressPrefix": "*",
                        "access": "Allow",
                        "direction": "Inbound",
                    }
                ]
            }
        )
        result = InboundAllowAllRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "NET-005"
        assert result.severity == Severity.CRITICAL

    def test_pass_when_no_allow_all(self) -> None:
        snap = _nsg_snap(
            {
                "securityRules": [
                    {
                        "destinationPortRange": "443",
                        "sourceAddressPrefix": "10.0.0.0/8",
                        "access": "Allow",
                        "direction": "Inbound",
                    }
                ]
            }
        )
        assert InboundAllowAllRule().evaluate(snap) is None


class TestNET006DDoSProtection:
    """NET-006: No DDoS protection on VNet."""

    def test_fail_when_no_ddos_and_internet_facing(self) -> None:
        snap = _vnet_snap(
            {"ddos_protection_enabled": False, "internet_facing": True}
        )
        result = DDoSProtectionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "NET-006"
        assert result.severity == Severity.MEDIUM

    def test_pass_when_ddos_enabled(self) -> None:
        snap = _vnet_snap(
            {"ddos_protection_enabled": True, "internet_facing": True}
        )
        assert DDoSProtectionRule().evaluate(snap) is None
