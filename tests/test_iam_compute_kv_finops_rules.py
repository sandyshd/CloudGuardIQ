"""Tests for NativeScanner IAM, Compute, KeyVault, and FinOps rules.

56 tests total - 2 per rule (pass case + fail case).
"""

from __future__ import annotations

from cloudguardiq.adapters.rules.azure.compute import (
    IdleVMRule,
    MissingCostTagsRule,
    NoBackupPolicyRule,
    OSDiskEncryptionRule,
    OutdatedOSImageRule,
    PublicIPDirectAttachedRule,
    UnmanagedDiskRule,
)
from cloudguardiq.adapters.rules.azure.finops import (
    AKSNoAutoscalerRule,
    AppGatewayLowUtilisationRule,
    DevTestOutsideBusinessHoursRule,
    EmptyLoadBalancerRule,
    HotTierBlobNotAccessedRule,
    OversizedVMRule,
    UnassignedPublicIPRule,
    UnattachedManagedDiskRule,
)
from cloudguardiq.adapters.rules.azure.iam import (
    ClassicAdminRoleRule,
    ExternalUserPrivilegedRoleRule,
    GuestPrivilegedRoleRule,
    NoMFAConditionalAccessRule,
    OwnerRoleDirectUserRule,
    OwnerRoleSubscriptionScopeRule,
    SPOwnerMultipleSubscriptionsRule,
    SPPasswordExpiryRule,
)
from cloudguardiq.adapters.rules.azure.keyvault import (
    NoDiagnosticLoggingRule,
    PublicNetworkAccessRule,
    PurgeProtectionRule,
    SecretNoExpiryRule,
    SoftDeleteRule,
)
from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import ResourceSnapshot


def _iam_snap(config=None):
    return ResourceSnapshot(
        subscription_id="sub-test", resource_group="rg-test",
        resource_type="Microsoft.Authorization/roleAssignments",
        resource_name="ra-test", region="global",
        provider=CloudProvider.AZURE, data_tier=DataTier.TIER1_NATIVE,
        config=config or {},
    )


def _vm_snap(config=None, cost_monthly=0.0, tags=None):
    return ResourceSnapshot(
        subscription_id="sub-test", resource_group="rg-test",
        resource_type="Microsoft.Compute/virtualMachines",
        resource_name="vm-test", region="eastus",
        provider=CloudProvider.AZURE, data_tier=DataTier.TIER1_NATIVE,
        config=config or {}, cost_monthly=cost_monthly, tags=tags or {},
    )


def _kv_snap(config=None):
    return ResourceSnapshot(
        subscription_id="sub-test", resource_group="rg-test",
        resource_type="Microsoft.KeyVault/vaults",
        resource_name="kv-test", region="eastus",
        provider=CloudProvider.AZURE, data_tier=DataTier.TIER1_NATIVE,
        config=config or {},
    )


def _finops_snap(resource_type="Microsoft.Compute/disks", resource_name="disk-test",
                 config=None, cost_monthly=0.0, tags=None):
    return ResourceSnapshot(
        subscription_id="sub-test", resource_group="rg-test",
        resource_type=resource_type, resource_name=resource_name,
        region="eastus", provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE, config=config or {},
        cost_monthly=cost_monthly, tags=tags or {},
    )


# IAM RULES


class TestIAM001OwnerRoleDirectUser:
    def test_fail_when_owner_assigned_to_user(self):
        snap = _iam_snap({"role_definition_name": "Owner", "principal_type": "User"})
        result = OwnerRoleDirectUserRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "IAM-001"
        assert result.severity == Severity.CRITICAL
        assert "CIS_1.1" in result.compliance_frameworks

    def test_pass_when_owner_assigned_to_service_principal(self):
        snap = _iam_snap({"role_definition_name": "Owner", "principal_type": "ServicePrincipal"})
        assert OwnerRoleDirectUserRule().evaluate(snap) is None


class TestIAM002OwnerRoleSubscriptionScope:
    def test_fail_when_owner_at_subscription_root(self):
        snap = _iam_snap({"role_definition_name": "Owner", "scope": "/subscriptions/sub-123"})
        result = OwnerRoleSubscriptionScopeRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "IAM-002"
        assert result.severity == Severity.CRITICAL

    def test_pass_when_owner_at_resource_group_scope(self):
        snap = _iam_snap(
            {"role_definition_name": "Owner",
             "scope": "/subscriptions/sub-123/resourceGroups/rg-test"}
        )
        assert OwnerRoleSubscriptionScopeRule().evaluate(snap) is None


class TestIAM003SPOwnerMultipleSubscriptions:
    def test_fail_when_sp_owns_multiple_subs(self):
        snap = _iam_snap(
            {"role_definition_name": "Owner",
             "principal_type": "ServicePrincipal",
             "owner_subscription_count": 3}
        )
        result = SPOwnerMultipleSubscriptionsRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "IAM-003"
        assert result.severity == Severity.CRITICAL

    def test_pass_when_sp_owns_single_sub(self):
        snap = _iam_snap(
            {"role_definition_name": "Owner",
             "principal_type": "ServicePrincipal",
             "owner_subscription_count": 1}
        )
        assert SPOwnerMultipleSubscriptionsRule().evaluate(snap) is None


class TestIAM004GuestPrivilegedRole:
    def test_fail_when_guest_has_contributor(self):
        snap = _iam_snap({"role_definition_name": "Contributor", "principal_type": "Guest"})
        result = GuestPrivilegedRoleRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "IAM-004"
        assert result.severity == Severity.HIGH

    def test_pass_when_guest_has_reader(self):
        snap = _iam_snap({"role_definition_name": "Reader", "principal_type": "Guest"})
        assert GuestPrivilegedRoleRule().evaluate(snap) is None


class TestIAM005ClassicAdminRole:
    def test_fail_when_classic_admin(self):
        snap = _iam_snap({"is_classic_admin": True})
        result = ClassicAdminRoleRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "IAM-005"
        assert result.severity == Severity.MEDIUM

    def test_pass_when_not_classic_admin(self):
        snap = _iam_snap({"is_classic_admin": False})
        assert ClassicAdminRoleRule().evaluate(snap) is None


class TestIAM006NoMFAConditionalAccess:
    def test_fail_when_mfa_not_enforced(self):
        snap = _iam_snap({"mfa_enforced": False})
        result = NoMFAConditionalAccessRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "IAM-006"
        assert result.severity == Severity.HIGH
        assert "SOC2_CC6.1" in result.compliance_frameworks

    def test_pass_when_mfa_enforced(self):
        snap = _iam_snap({"mfa_enforced": True})
        assert NoMFAConditionalAccessRule().evaluate(snap) is None


class TestIAM007ExternalUserPrivilegedRole:
    def test_fail_when_external_user_has_owner(self):
        snap = _iam_snap({"role_definition_name": "Owner", "is_external_user": True})
        result = ExternalUserPrivilegedRoleRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "IAM-007"
        assert result.severity == Severity.HIGH

    def test_pass_when_internal_user(self):
        snap = _iam_snap({"role_definition_name": "Owner", "is_external_user": False})
        assert ExternalUserPrivilegedRoleRule().evaluate(snap) is None


class TestIAM008SPPasswordExpiry:
    def test_fail_when_expiry_exceeds_365_days(self):
        snap = _iam_snap({"credential_expiry_days": 730})
        result = SPPasswordExpiryRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "IAM-008"
        assert result.severity == Severity.MEDIUM

    def test_pass_when_expiry_within_365_days(self):
        snap = _iam_snap({"credential_expiry_days": 180})
        assert SPPasswordExpiryRule().evaluate(snap) is None


# COMPUTE RULES


class TestVM001OSDiskEncryption:
    def test_fail_when_encryption_disabled(self):
        snap = _vm_snap({"os_disk_encryption_enabled": False})
        result = OSDiskEncryptionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "VM-001"
        assert result.severity == Severity.HIGH
        assert "NIST_SC-28" in result.compliance_frameworks

    def test_pass_when_encryption_enabled(self):
        snap = _vm_snap({"os_disk_encryption_enabled": True})
        assert OSDiskEncryptionRule().evaluate(snap) is None


class TestVM002UnmanagedDisk:
    def test_fail_when_unmanaged_disk(self):
        snap = _vm_snap({"uses_unmanaged_disk": True})
        result = UnmanagedDiskRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "VM-002"
        assert result.severity == Severity.MEDIUM

    def test_pass_when_managed_disk(self):
        snap = _vm_snap({"uses_unmanaged_disk": False})
        assert UnmanagedDiskRule().evaluate(snap) is None


class TestVM003NoBackupPolicy:
    def test_fail_when_no_backup(self):
        snap = _vm_snap({"backup_policy_enabled": False})
        result = NoBackupPolicyRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "VM-003"
        assert result.severity == Severity.MEDIUM

    def test_pass_when_backup_enabled(self):
        snap = _vm_snap({"backup_policy_enabled": True})
        assert NoBackupPolicyRule().evaluate(snap) is None


class TestVM004PublicIPDirectAttached:
    def test_fail_when_public_ip_attached(self):
        snap = _vm_snap({"public_ip_directly_attached": True})
        result = PublicIPDirectAttachedRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "VM-004"
        assert result.severity == Severity.HIGH

    def test_pass_when_no_public_ip(self):
        snap = _vm_snap({"public_ip_directly_attached": False})
        assert PublicIPDirectAttachedRule().evaluate(snap) is None


class TestVM005OutdatedOSImage:
    def test_fail_when_outdated_os(self):
        snap = _vm_snap({"os_image": "Ubuntu 18.04 LTS"})
        result = OutdatedOSImageRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "VM-005"
        assert result.severity == Severity.MEDIUM

    def test_pass_when_current_os(self):
        snap = _vm_snap({"os_image": "Ubuntu 22.04 LTS"})
        assert OutdatedOSImageRule().evaluate(snap) is None


class TestVM006MissingCostTags:
    def test_fail_when_tags_missing(self):
        snap = _vm_snap(tags={"environment": "prod"})
        result = MissingCostTagsRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "VM-006"
        assert result.severity == Severity.LOW
        assert result.finding_type == FindingType.FINOPS

    def test_pass_when_all_tags_present(self):
        snap = _vm_snap(tags={"environment": "prod", "owner": "team-a", "cost-center": "cc-100"})
        assert MissingCostTagsRule().evaluate(snap) is None


class TestVM007IdleVM:
    def test_fail_when_idle(self):
        snap = _vm_snap({"avg_cpu_7d": 2.0}, cost_monthly=150.0)
        result = IdleVMRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "VM-007"
        assert result.severity == Severity.HIGH
        assert result.waste_monthly_usd == 150.0

    def test_pass_when_cpu_normal(self):
        snap = _vm_snap({"avg_cpu_7d": 50.0}, cost_monthly=150.0)
        assert IdleVMRule().evaluate(snap) is None


# KEY VAULT RULES


class TestKV001SoftDelete:
    def test_fail_when_soft_delete_disabled(self):
        snap = _kv_snap({"soft_delete_enabled": False})
        result = SoftDeleteRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "KV-001"
        assert result.severity == Severity.CRITICAL
        assert "CIS_8.1" in result.compliance_frameworks

    def test_pass_when_soft_delete_enabled(self):
        snap = _kv_snap({"soft_delete_enabled": True})
        assert SoftDeleteRule().evaluate(snap) is None


class TestKV002PurgeProtection:
    def test_fail_when_purge_protection_disabled(self):
        snap = _kv_snap({"purge_protection_enabled": False})
        result = PurgeProtectionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "KV-002"
        assert result.severity == Severity.HIGH

    def test_pass_when_purge_protection_enabled(self):
        snap = _kv_snap({"purge_protection_enabled": True})
        assert PurgeProtectionRule().evaluate(snap) is None


class TestKV003PublicNetworkAccess:
    def test_fail_when_public_access_enabled(self):
        snap = _kv_snap({"public_network_access_enabled": True})
        result = PublicNetworkAccessRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "KV-003"
        assert result.severity == Severity.HIGH
        assert "NIST_SC-7" in result.compliance_frameworks

    def test_pass_when_public_access_disabled(self):
        snap = _kv_snap({"public_network_access_enabled": False})
        assert PublicNetworkAccessRule().evaluate(snap) is None


class TestKV004NoDiagnosticLogging:
    def test_fail_when_no_logging(self):
        snap = _kv_snap({"diagnostic_logging_enabled": False})
        result = NoDiagnosticLoggingRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "KV-004"
        assert result.severity == Severity.MEDIUM
        assert "SOC2_CC7.2" in result.compliance_frameworks

    def test_pass_when_logging_enabled(self):
        snap = _kv_snap({"diagnostic_logging_enabled": True})
        assert NoDiagnosticLoggingRule().evaluate(snap) is None


class TestKV005SecretNoExpiry:
    def test_fail_when_secrets_have_no_expiry(self):
        snap = _kv_snap({"secrets_without_expiry": 3})
        result = SecretNoExpiryRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "KV-005"
        assert result.severity == Severity.MEDIUM

    def test_pass_when_all_secrets_have_expiry(self):
        snap = _kv_snap({"secrets_without_expiry": 0})
        assert SecretNoExpiryRule().evaluate(snap) is None


# FINOPS RULES


class TestFIN001UnattachedManagedDisk:
    def test_fail_when_unattached(self):
        snap = _finops_snap(config={"disk_state": "Unattached"}, cost_monthly=25.0)
        result = UnattachedManagedDiskRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "FIN-001"
        assert result.waste_monthly_usd == 25.0

    def test_pass_when_attached(self):
        snap = _finops_snap(config={"disk_state": "Attached"}, cost_monthly=25.0)
        assert UnattachedManagedDiskRule().evaluate(snap) is None


class TestFIN002UnassignedPublicIP:
    def test_fail_when_unassigned(self):
        snap = _finops_snap(
            resource_type="Microsoft.Network/publicIPAddresses",
            resource_name="pip-test",
            config={"ip_association": None}
        )
        result = UnassignedPublicIPRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "FIN-002"
        assert result.waste_monthly_usd == 3.65

    def test_pass_when_assigned(self):
        snap = _finops_snap(
            resource_type="Microsoft.Network/publicIPAddresses",
            resource_name="pip-test",
            config={"ip_association": "/subscriptions/sub/nic/nic-1"}
        )
        assert UnassignedPublicIPRule().evaluate(snap) is None


class TestFIN003EmptyLoadBalancer:
    def test_fail_when_no_backend(self):
        snap = _finops_snap(
            resource_type="Microsoft.Network/loadBalancers",
            resource_name="lb-test",
            config={"backend_pool_count": 0},
            cost_monthly=50.0
        )
        result = EmptyLoadBalancerRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "FIN-003"
        assert result.waste_monthly_usd == 50.0

    def test_pass_when_backend_configured(self):
        snap = _finops_snap(
            resource_type="Microsoft.Network/loadBalancers",
            resource_name="lb-test",
            config={"backend_pool_count": 2},
            cost_monthly=50.0
        )
        assert EmptyLoadBalancerRule().evaluate(snap) is None


class TestFIN004HotTierBlobNotAccessed:
    def test_fail_when_hot_blob_stale(self):
        snap = _finops_snap(
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="sa-test",
            config={"access_tier": "Hot", "days_since_last_access": 45},
            cost_monthly=100.0
        )
        result = HotTierBlobNotAccessedRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "FIN-004"
        # Heuristic rules report ESTIMATED savings (not DIRECT waste).
        assert result.finops_method == "ESTIMATED"
        assert result.finops_confidence == "MEDIUM"
        assert result.estimated_impact_monthly_usd == 40.0
        assert result.waste_monthly_usd == 0.0

    def test_pass_when_recently_accessed(self):
        snap = _finops_snap(
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="sa-test",
            config={"access_tier": "Hot", "days_since_last_access": 10},
            cost_monthly=100.0
        )
        assert HotTierBlobNotAccessedRule().evaluate(snap) is None


class TestFIN005OversizedVM:
    def test_fail_when_underutilised(self):
        snap = _finops_snap(
            resource_type="Microsoft.Compute/virtualMachines",
            resource_name="vm-big",
            config={"avg_cpu_7d": 5.0, "avg_memory_7d": 8.0},
            cost_monthly=200.0
        )
        result = OversizedVMRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "FIN-005"
        # Heuristic rules report ESTIMATED savings (not DIRECT waste).
        assert result.finops_method == "ESTIMATED"
        assert result.finops_confidence == "MEDIUM"
        assert result.estimated_impact_monthly_usd == 100.0
        assert result.waste_monthly_usd == 0.0

    def test_pass_when_well_utilised(self):
        snap = _finops_snap(
            resource_type="Microsoft.Compute/virtualMachines",
            resource_name="vm-big",
            config={"avg_cpu_7d": 50.0, "avg_memory_7d": 60.0},
            cost_monthly=200.0
        )
        assert OversizedVMRule().evaluate(snap) is None


class TestFIN006DevTestOutsideBusinessHours:
    def test_fail_when_dev_no_autoshutdown(self):
        snap = _finops_snap(
            resource_type="Microsoft.Compute/virtualMachines",
            resource_name="vm-dev",
            config={"auto_shutdown_enabled": False},
            cost_monthly=100.0,
            tags={"environment": "dev"}
        )
        result = DevTestOutsideBusinessHoursRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "FIN-006"
        # Heuristic rules report ESTIMATED savings (not DIRECT waste).
        assert result.finops_method == "ESTIMATED"
        assert result.finops_confidence == "MEDIUM"
        assert result.estimated_impact_monthly_usd == 65.0
        assert result.waste_monthly_usd == 0.0

    def test_pass_when_prod_resource(self):
        snap = _finops_snap(
            resource_type="Microsoft.Compute/virtualMachines",
            resource_name="vm-prod",
            config={"auto_shutdown_enabled": False},
            cost_monthly=100.0,
            tags={"environment": "prod"}
        )
        assert DevTestOutsideBusinessHoursRule().evaluate(snap) is None


class TestFIN007AppGatewayLowUtilisation:
    def test_fail_when_low_utilisation(self):
        snap = _finops_snap(
            resource_type="Microsoft.Network/applicationGateways",
            resource_name="appgw-test",
            config={"capacity_utilisation_pct": 5.0},
            cost_monthly=300.0
        )
        result = AppGatewayLowUtilisationRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "FIN-007"
        # Heuristic rules report ESTIMATED savings (not DIRECT waste).
        assert result.finops_method == "ESTIMATED"
        assert result.finops_confidence == "MEDIUM"
        assert result.estimated_impact_monthly_usd == 210.0
        assert result.waste_monthly_usd == 0.0

    def test_pass_when_well_utilised(self):
        snap = _finops_snap(
            resource_type="Microsoft.Network/applicationGateways",
            resource_name="appgw-test",
            config={"capacity_utilisation_pct": 60.0},
            cost_monthly=300.0
        )
        assert AppGatewayLowUtilisationRule().evaluate(snap) is None


class TestFIN008AKSNoAutoscaler:
    def test_fail_when_no_autoscaler(self):
        snap = _finops_snap(
            resource_type="Microsoft.ContainerService/managedClusters",
            resource_name="aks-test",
            config={"autoscaler_enabled": False},
            cost_monthly=500.0
        )
        result = AKSNoAutoscalerRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "FIN-008"
        # Heuristic rules report ESTIMATED savings (not DIRECT waste).
        assert result.finops_method == "ESTIMATED"
        assert result.finops_confidence == "MEDIUM"
        assert result.estimated_impact_monthly_usd == 150.0
        assert result.waste_monthly_usd == 0.0

    def test_pass_when_autoscaler_enabled(self):
        snap = _finops_snap(
            resource_type="Microsoft.ContainerService/managedClusters",
            resource_name="aks-test",
            config={"autoscaler_enabled": True},
            cost_monthly=500.0
        )
        assert AKSNoAutoscalerRule().evaluate(snap) is None
