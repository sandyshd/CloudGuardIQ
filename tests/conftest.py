"""Shared test fixtures for CloudGuardIQ tests."""

from __future__ import annotations

import pytest

from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import ResourceSnapshot


@pytest.fixture
def storage_snapshot() -> ResourceSnapshot:
    """A storage account ResourceSnapshot for testing."""
    return ResourceSnapshot(
        subscription_id="sub-123",
        resource_group="rg1",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="sa1",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={"supportsHttpsTrafficOnly": True, "allowBlobPublicAccess": False},
    )


@pytest.fixture
def insecure_storage_snapshot() -> ResourceSnapshot:
    """A storage account with security issues."""
    return ResourceSnapshot(
        subscription_id="sub-123",
        resource_group="rg1",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="sa2",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={"supportsHttpsTrafficOnly": False, "allowBlobPublicAccess": True},
    )


@pytest.fixture
def nsg_snapshot() -> ResourceSnapshot:
    """An NSG ResourceSnapshot with open SSH."""
    return ResourceSnapshot(
        subscription_id="sub-123",
        resource_group="rg1",
        resource_type="Microsoft.Network/networkSecurityGroups",
        resource_name="nsg1",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={
            "securityRules": [
                {
                    "destinationPortRange": "22",
                    "sourceAddressPrefix": "*",
                    "access": "Allow",
                    "direction": "Inbound",
                }
            ]
        },
    )


@pytest.fixture
def vm_snapshot() -> ResourceSnapshot:
    """A VM ResourceSnapshot."""
    return ResourceSnapshot(
        subscription_id="sub-123",
        resource_group="rg1",
        resource_type="Microsoft.Compute/virtualMachines",
        resource_name="vm1",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={"encryptionAtHost": False, "avgCpuPercent": 2.0},
        cost_monthly=150.0,
    )


@pytest.fixture
def keyvault_snapshot() -> ResourceSnapshot:
    """A Key Vault ResourceSnapshot."""
    return ResourceSnapshot(
        subscription_id="sub-123",
        resource_group="rg1",
        resource_type="Microsoft.KeyVault/vaults",
        resource_name="kv1",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={"enableSoftDelete": False, "enablePurgeProtection": False},
    )


@pytest.fixture
def disk_snapshot() -> ResourceSnapshot:
    """An unattached disk ResourceSnapshot."""
    return ResourceSnapshot(
        subscription_id="sub-123",
        resource_group="rg1",
        resource_type="Microsoft.Compute/disks",
        resource_name="disk1",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={"diskState": "Unattached"},
        cost_monthly=25.0,
    )


@pytest.fixture
def role_assignment_snapshot() -> ResourceSnapshot:
    """A role assignment ResourceSnapshot."""
    return ResourceSnapshot(
        subscription_id="sub-123",
        resource_group="",
        resource_type="Microsoft.Authorization/roleAssignments",
        resource_name="ra1",
        region="global",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={
            "roleDefinitionName": "Owner",
            "scope": "/subscriptions/sub-123",
        },
    )
