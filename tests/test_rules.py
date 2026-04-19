"""Tests for scanner rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.compute import VMNoEncryptionRule, VMUnmanagedDisksRule
from cloudguardiq.adapters.rules.finops import UnattachedDiskRule, UnderutilizedVMRule
from cloudguardiq.adapters.rules.iam import OverprivilegedIdentityRule
from cloudguardiq.adapters.rules.keyvault import KeyVaultPurgeProtectionRule, KeyVaultSoftDeleteRule
from cloudguardiq.adapters.rules.network import NSGOpenRDPRule, NSGOpenSSHRule
from cloudguardiq.adapters.rules.storage import StorageHttpsOnlyRule, StoragePublicAccessRule
from cloudguardiq.core.enums import CloudProvider, DataTier, FindingCategory, Severity
from cloudguardiq.core.models import ResourceSnapshot


class TestStorageRules:
    def test_https_only_pass(self, storage_snapshot: ResourceSnapshot) -> None:
        rule = StorageHttpsOnlyRule()
        findings = rule.evaluate(storage_snapshot)
        assert len(findings) == 0

    def test_https_only_fail(self, insecure_storage_snapshot: ResourceSnapshot) -> None:
        rule = StorageHttpsOnlyRule()
        findings = rule.evaluate(insecure_storage_snapshot)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].rule_id == "STORAGE_HTTPS_ONLY"

    def test_public_access_pass(self, storage_snapshot: ResourceSnapshot) -> None:
        rule = StoragePublicAccessRule()
        findings = rule.evaluate(storage_snapshot)
        assert len(findings) == 0

    def test_public_access_fail(self, insecure_storage_snapshot: ResourceSnapshot) -> None:
        rule = StoragePublicAccessRule()
        findings = rule.evaluate(insecure_storage_snapshot)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].category == FindingCategory.SECURITY


class TestNetworkRules:
    def test_open_ssh_detected(self, nsg_snapshot: ResourceSnapshot) -> None:
        rule = NSGOpenSSHRule()
        findings = rule.evaluate(nsg_snapshot)
        assert len(findings) == 1
        assert findings[0].rule_id == "NSG_OPEN_SSH"

    def test_open_rdp_not_detected(self, nsg_snapshot: ResourceSnapshot) -> None:
        rule = NSGOpenRDPRule()
        findings = rule.evaluate(nsg_snapshot)
        assert len(findings) == 0

    def test_open_rdp_detected(self) -> None:
        snap = ResourceSnapshot(
            subscription_id="sub-1",
            resource_group="rg",
            resource_type="Microsoft.Network/networkSecurityGroups",
            resource_name="nsg2",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
            config={
                "securityRules": [
                    {
                        "destinationPortRange": "3389",
                        "sourceAddressPrefix": "0.0.0.0/0",
                        "access": "Allow",
                        "direction": "Inbound",
                    }
                ]
            },
        )
        rule = NSGOpenRDPRule()
        findings = rule.evaluate(snap)
        assert len(findings) == 1

    def test_closed_nsg_clean(self) -> None:
        snap = ResourceSnapshot(
            subscription_id="sub-1",
            resource_group="rg",
            resource_type="Microsoft.Network/networkSecurityGroups",
            resource_name="nsg3",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
            config={
                "securityRules": [
                    {
                        "destinationPortRange": "22",
                        "sourceAddressPrefix": "10.0.0.0/8",
                        "access": "Allow",
                        "direction": "Inbound",
                    }
                ]
            },
        )
        assert len(NSGOpenSSHRule().evaluate(snap)) == 0


class TestComputeRules:
    def test_no_encryption_detected(self, vm_snapshot: ResourceSnapshot) -> None:
        rule = VMNoEncryptionRule()
        findings = rule.evaluate(vm_snapshot)
        assert len(findings) == 1
        assert findings[0].rule_id == "COMPUTE_NO_ENCRYPTION"

    def test_unmanaged_disks_clean(self, vm_snapshot: ResourceSnapshot) -> None:
        rule = VMUnmanagedDisksRule()
        findings = rule.evaluate(vm_snapshot)
        assert len(findings) == 0

    def test_unmanaged_disks_detected(self) -> None:
        snap = ResourceSnapshot(
            subscription_id="sub-1",
            resource_group="rg",
            resource_type="Microsoft.Compute/virtualMachines",
            resource_name="vm2",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
            config={"storageProfile": {"osDisk": {"vhd": {"uri": "https://blob/vhd"}}}},
        )
        rule = VMUnmanagedDisksRule()
        findings = rule.evaluate(snap)
        assert len(findings) == 1


class TestKeyVaultRules:
    def test_soft_delete_disabled(self, keyvault_snapshot: ResourceSnapshot) -> None:
        rule = KeyVaultSoftDeleteRule()
        findings = rule.evaluate(keyvault_snapshot)
        assert len(findings) == 1

    def test_purge_protection_disabled(self, keyvault_snapshot: ResourceSnapshot) -> None:
        rule = KeyVaultPurgeProtectionRule()
        findings = rule.evaluate(keyvault_snapshot)
        assert len(findings) == 1


class TestIAMRules:
    def test_overprivileged_detected(self, role_assignment_snapshot: ResourceSnapshot) -> None:
        rule = OverprivilegedIdentityRule()
        findings = rule.evaluate(role_assignment_snapshot)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_contributor_ok(self) -> None:
        snap = ResourceSnapshot(
            subscription_id="sub-1",
            resource_group="",
            resource_type="Microsoft.Authorization/roleAssignments",
            resource_name="ra2",
            region="global",
            data_tier=DataTier.TIER1_NATIVE,
            config={"roleDefinitionName": "Contributor", "scope": "/subscriptions/sub-1"},
        )
        rule = OverprivilegedIdentityRule()
        assert len(rule.evaluate(snap)) == 0


class TestFinOpsRules:
    def test_underutilized_vm(self, vm_snapshot: ResourceSnapshot) -> None:
        rule = UnderutilizedVMRule()
        findings = rule.evaluate(vm_snapshot)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.COST

    def test_utilized_vm_clean(self) -> None:
        snap = ResourceSnapshot(
            subscription_id="sub-1",
            resource_group="rg",
            resource_type="Microsoft.Compute/virtualMachines",
            resource_name="vm3",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
            config={"avgCpuPercent": 50.0},
            cost_monthly=100.0,
        )
        rule = UnderutilizedVMRule()
        assert len(rule.evaluate(snap)) == 0

    def test_unattached_disk(self, disk_snapshot: ResourceSnapshot) -> None:
        rule = UnattachedDiskRule()
        findings = rule.evaluate(disk_snapshot)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.COST
