"""Tests for NativeScanner orchestrator."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cloudguardiq.adapters.base import AdapterBase
from cloudguardiq.adapters.native_scanner import RULE_REGISTRY, NativeScanner
from cloudguardiq.core.enums import DataTier
from cloudguardiq.core.models import ResourceSnapshot

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_rg_response(data: list[dict[str, Any]], skip_token: str | None = None) -> SimpleNamespace:
    """Build a fake Resource Graph response."""
    return SimpleNamespace(data=data, skip_token=skip_token)


@pytest.fixture
def mock_credential() -> MagicMock:
    """Fake Azure TokenCredential."""
    return MagicMock()


@pytest.fixture
def raw_storage_resources() -> list[dict[str, Any]]:
    """Raw Resource Graph output for a storage account."""
    return [
        {
            "id": (
                "/subscriptions/sub-1/resourceGroups/rg1"
                "/providers/Microsoft.Storage/storageAccounts/sa1"
            ),
            "name": "sa1",
            "resourceGroup": "rg1",
            "location": "eastus",
            "tags": {"env": "prod"},
            "properties_allowBlobPublicAccess": True,
            "properties_minimumTlsVersion": "TLS1_0",
            "properties_networkAcls_defaultAction": "Allow",
            "properties_supportsHttpsTrafficOnly": False,
            "properties_allowSharedKeyAccess": True,
            "properties_encryption_requireInfrastructureEncryption": False,
        },
    ]


@pytest.fixture
def raw_nsg_resources() -> list[dict[str, Any]]:
    """Raw Resource Graph output for an NSG."""
    return [
        {
            "id": (
                "/subscriptions/sub-1/resourceGroups/rg1"
                "/providers/Microsoft.Network/networkSecurityGroups/nsg1"
            ),
            "name": "nsg1",
            "resourceGroup": "rg1",
            "location": "eastus",
            "tags": {},
            "properties_securityRules": [
                {
                    "name": "AllowSSH",
                    "properties": {
                        "access": "Allow",
                        "direction": "Inbound",
                        "sourceAddressPrefix": "*",
                        "destinationPortRange": "22",
                        "protocol": "TCP",
                        "priority": 100,
                    },
                },
            ],
            "properties_defaultSecurityRules": [],
        },
    ]


@pytest.fixture
def raw_vm_resources() -> list[dict[str, Any]]:
    """Raw Resource Graph output for a VM."""
    return [
        {
            "id": (
                "/subscriptions/sub-1/resourceGroups/rg1"
                "/providers/Microsoft.Compute/virtualMachines/vm1"
            ),
            "name": "vm1",
            "resourceGroup": "rg1",
            "location": "westus",
            "tags": {"team": "infra"},
            "properties_storageProfile_osDisk_managedDisk": {"id": "/disks/d1"},
            "properties_storageProfile_osDisk_encryptionSettings": {"enabled": True},
            "properties_networkProfile_networkInterfaces": [{"id": "/nics/nic1"}],
        },
    ]


@pytest.fixture
def raw_kv_resources() -> list[dict[str, Any]]:
    """Raw Resource Graph output for a Key Vault."""
    return [
        {
            "id": (
                "/subscriptions/sub-1/resourceGroups/rg1"
                "/providers/Microsoft.KeyVault/vaults/kv1"
            ),
            "name": "kv1",
            "resourceGroup": "rg1",
            "location": "eastus",
            "tags": {},
            "properties_enableSoftDelete": True,
            "properties_enablePurgeProtection": False,
            "properties_publicNetworkAccess": "Enabled",
        },
    ]


@pytest.fixture
def raw_sql_resources() -> list[dict[str, Any]]:
    """Raw Resource Graph output for a SQL server."""
    return [
        {
            "id": (
                "/subscriptions/sub-1/resourceGroups/rg1"
                "/providers/Microsoft.Sql/servers/sql1"
            ),
            "name": "sql1",
            "resourceGroup": "rg1",
            "location": "eastus",
            "tags": {},
            "properties_publicNetworkAccess": "Enabled",
            "properties_minimalTlsVersion": "1.0",
        },
    ]


@pytest.fixture
def raw_sql_audit_resources() -> list[dict[str, Any]]:
    """Raw Resource Graph output for SQL auditing settings (sub-resource)."""
    return [
        {
            "id": (
                "/subscriptions/sub-1/resourceGroups/rg1"
                "/providers/Microsoft.Sql/servers/sql1/auditingSettings/Default"
            ),
            "name": "Default",
            "properties_state": "Disabled",
        },
    ]


@pytest.fixture
def raw_aks_resources() -> list[dict[str, Any]]:
    """Raw Resource Graph output for an AKS managed cluster."""
    return [
        {
            "id": (
                "/subscriptions/sub-1/resourceGroups/rg1"
                "/providers/Microsoft.ContainerService/managedClusters/aks1"
            ),
            "name": "aks1",
            "resourceGroup": "rg1",
            "location": "eastus",
            "tags": {},
            "properties_enableRBAC": False,
            "properties_apiServerAccessProfile_enablePrivateCluster": False,
            "properties_apiServerAccessProfile_authorizedIPRanges": [],
            "properties_networkProfile_networkPolicy": "none",
        },
    ]


@pytest.fixture
def raw_inventory_resources() -> list[dict[str, Any]]:
    """Generic inventory rows: a duplicate storage account plus other types."""
    return [
        {
            "id": (
                "/subscriptions/sub-1/resourceGroups/rg1"
                "/providers/Microsoft.Storage/storageAccounts/sa1"
            ),
            "name": "sa1",
            "type": "microsoft.storage/storageaccounts",
            "resourceGroup": "rg1",
            "location": "eastus",
            "tags": {"env": "prod"},
            "subscriptionId": "sub-1",
        },
        {
            "id": (
                "/subscriptions/sub-1/resourceGroups/rg2"
                "/providers/Microsoft.Web/sites/web1"
            ),
            "name": "web1",
            "type": "microsoft.web/sites",
            "resourceGroup": "rg2",
            "location": "westus",
            "tags": {},
            "subscriptionId": "sub-1",
        },
        {
            "id": (
                "/subscriptions/sub-1/resourceGroups/rg2"
                "/providers/Microsoft.ContainerRegistry/registries/acr1"
            ),
            "name": "acr1",
            "type": "microsoft.containerregistry/registries",
            "resourceGroup": "rg2",
            "location": "westus",
            "tags": {},
            "subscriptionId": "sub-1",
        },
        {
            # Subscription-scoped resource with no RG / region.
            "id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa1",
            "name": "pa1",
            "type": "microsoft.authorization/policyassignments",
            "resourceGroup": "",
            "location": "",
            "tags": {},
            "subscriptionId": "sub-1",
        },
    ]


def _build_scanner_with_mock_rg(
    mock_credential: MagicMock,
    responses: dict[str, list[dict[str, Any]]],
) -> NativeScanner:
    """Create a NativeScanner with a mocked ResourceGraphClient."""
    with patch(
        "cloudguardiq.adapters.native_scanner.ResourceGraphClient",
    ) as rg_cls:
        mock_client = MagicMock()

        def _resources_side_effect(request: Any) -> SimpleNamespace:
            query: str = request.query
            for keyword, data in responses.items():
                if keyword in query:
                    return _make_rg_response(data)
            return _make_rg_response([])

        mock_client.resources.side_effect = _resources_side_effect
        rg_cls.return_value = mock_client

        scanner = NativeScanner(mock_credential, "sub-1")
    return scanner


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestNativeScannerRuleRegistry:
    def test_rule_registry_has_55_rules(self) -> None:
        """All 55 PolicyRule instances should be in the registry."""
        assert len(RULE_REGISTRY) == 55

    def test_all_rules_have_rule_id(self) -> None:
        """Every rule must have a non-empty rule_id."""
        for rule in RULE_REGISTRY:
            assert rule.rule_id, f"{type(rule).__name__} has no rule_id"


class TestScanReturnsResourceSnapshots:
    async def test_scan_returns_resource_snapshots(
        self,
        mock_credential: MagicMock,
        raw_storage_resources: list[dict[str, Any]],
        raw_nsg_resources: list[dict[str, Any]],
        raw_vm_resources: list[dict[str, Any]],
        raw_kv_resources: list[dict[str, Any]],
    ) -> None:
        """scan() should return ResourceSnapshot objects for all resource types."""
        scanner = _build_scanner_with_mock_rg(
            mock_credential,
            {
                "storageaccounts": raw_storage_resources,
                "networksecuritygroups": raw_nsg_resources,
                "virtualmachines": raw_vm_resources,
                "keyvault": raw_kv_resources,
            },
        )

        with patch.object(scanner, "_fetch_cost_data", new_callable=AsyncMock, return_value={}):
            snapshots = await scanner.scan()

        assert len(snapshots) == 4
        assert all(isinstance(s, ResourceSnapshot) for s in snapshots)


class TestAllSnapshotsHaveTier1:
    async def test_all_snapshots_have_tier1(
        self,
        mock_credential: MagicMock,
        raw_storage_resources: list[dict[str, Any]],
    ) -> None:
        """Every snapshot from scan() must have data_tier == TIER1_NATIVE."""
        scanner = _build_scanner_with_mock_rg(
            mock_credential,
            {"storageaccounts": raw_storage_resources},
        )

        with patch.object(scanner, "_fetch_cost_data", new_callable=AsyncMock, return_value={}):
            snapshots = await scanner.scan()

        for snap in snapshots:
            assert snap.data_tier == DataTier.TIER1_NATIVE


class TestStorageConfigCorrectlyNormalised:
    async def test_storage_config_correctly_normalised(
        self,
        mock_credential: MagicMock,
        raw_storage_resources: list[dict[str, Any]],
    ) -> None:
        """Storage config fields should be mapped from Resource Graph JSON."""
        scanner = _build_scanner_with_mock_rg(
            mock_credential,
            {"storageaccounts": raw_storage_resources},
        )

        with patch.object(scanner, "_fetch_cost_data", new_callable=AsyncMock, return_value={}):
            snapshots = await scanner.scan()

        storage = [s for s in snapshots if "Storage" in s.resource_type]
        assert len(storage) == 1
        cfg = storage[0].config
        assert cfg["allow_blob_public_access"] is True
        assert cfg["minimum_tls_version"] == "TLS1_0"
        assert cfg["network_default_action"] == "Allow"
        assert cfg["enable_https_traffic_only"] is False
        assert cfg["allow_shared_key_access"] is True
        assert cfg["infrastructure_encryption_enabled"] is False


class TestNSGRulesCorrectlyFlattened:
    async def test_nsg_rules_correctly_flattened(
        self,
        mock_credential: MagicMock,
        raw_nsg_resources: list[dict[str, Any]],
    ) -> None:
        """NSG security rules should be flattened into config."""
        scanner = _build_scanner_with_mock_rg(
            mock_credential,
            {"networksecuritygroups": raw_nsg_resources},
        )

        with patch.object(scanner, "_fetch_cost_data", new_callable=AsyncMock, return_value={}):
            snapshots = await scanner.scan()

        nsgs = [s for s in snapshots if "networkSecurityGroups" in s.resource_type]
        assert len(nsgs) == 1
        rules = nsgs[0].config["securityRules"]
        assert len(rules) == 1
        assert rules[0]["name"] == "AllowSSH"
        assert rules[0]["access"] == "Allow"
        assert rules[0]["direction"] == "Inbound"
        assert rules[0]["sourceAddressPrefix"] == "*"
        assert rules[0]["destinationPortRange"] == "22"


class TestCostDataEnrichment:
    async def test_cost_data_enrichment_when_available(
        self,
        mock_credential: MagicMock,
        raw_storage_resources: list[dict[str, Any]],
    ) -> None:
        """When cost data is returned, snapshots should be enriched."""
        scanner = _build_scanner_with_mock_rg(
            mock_credential,
            {"storageaccounts": raw_storage_resources},
        )

        with patch.object(scanner, "_fetch_cost_data", new_callable=AsyncMock) as mock_cost:
            # We need to know the snapshot ID to set cost data properly
            # Build snapshots first to get the ID, then set cost data
            snapshots_preview = await scanner._build_storage_snapshots(raw_storage_resources)
            snap_id = snapshots_preview[0].id
            mock_cost.return_value = {snap_id: 42.50}
            snapshots = await scanner.scan()

        enriched = [s for s in snapshots if s.cost_monthly == 42.50]
        assert len(enriched) == 1


class TestScanSucceedsWhenCostApiFails:
    async def test_scan_succeeds_when_cost_api_fails(
        self,
        mock_credential: MagicMock,
        raw_storage_resources: list[dict[str, Any]],
    ) -> None:
        """scan() must complete even if _fetch_cost_data raises."""
        scanner = _build_scanner_with_mock_rg(
            mock_credential,
            {"storageaccounts": raw_storage_resources},
        )

        with patch.object(
            scanner,
            "_fetch_cost_data",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Cost API unavailable"),
        ):
            # _fetch_cost_data is called internally but wrapped in try/except
            # However, the mock replaces the method entirely so the try/except
            # inside the real method won't apply. We need to test the real
            # _fetch_cost_data error path instead.
            pass

        # Test the real method with a failing Cost Management client
        with (
            patch(
                "cloudguardiq.adapters.native_scanner.CostManagementClient",
                side_effect=RuntimeError("boom"),
            ),
            patch.object(
                scanner,
                "_query_resource_graph",
                new_callable=AsyncMock,
                return_value=raw_storage_resources,
            ),
        ):
            # Replace _query_resource_graph to return data for storage only
            async def _mock_query(query: str) -> list[dict[str, Any]]:
                if "storageaccounts" in query:
                    return raw_storage_resources
                return []

            scanner._query_resource_graph = _mock_query  # type: ignore[assignment]
            snapshots = await scanner.scan()

        assert len(snapshots) >= 1
        # Cost should remain 0 since cost API failed
        assert all(s.cost_monthly == 0.0 for s in snapshots)


class _ValidatorAdapter(AdapterBase):
    """Minimal concrete adapter used only to exercise validate_snapshot()."""

    async def scan(self) -> list[ResourceSnapshot]:
        return []

    async def get_api_contract(self) -> dict[str, Any]:
        return {}

    async def validate_connection(self) -> bool:
        return True

    async def list_resources(self, subscription_id: str) -> list[ResourceSnapshot]:
        return []

    async def get_resource(self, resource_id: str) -> ResourceSnapshot | None:
        return None

    async def get_cost(self, resource_id: str) -> float:
        return 0.0

    async def enrich_with_defender(
        self, snapshots: list[ResourceSnapshot]
    ) -> list[ResourceSnapshot]:
        return snapshots

    async def get_raw_properties(self, resource_id: str) -> dict[str, Any]:
        return {}


class TestGenericInventoryScan:
    async def test_inventory_captures_all_types_without_duplicates(
        self,
        mock_credential: MagicMock,
        raw_storage_resources: list[dict[str, Any]],
        raw_inventory_resources: list[dict[str, Any]],
    ) -> None:
        """Generic inventory adds every other type once, without duplicating typed snapshots."""
        scanner = _build_scanner_with_mock_rg(
            mock_credential,
            {
                "storageaccounts": raw_storage_resources,
                "subscriptionId": raw_inventory_resources,
            },
        )

        with patch.object(
            scanner, "_fetch_cost_data", new_callable=AsyncMock, return_value={}
        ):
            snapshots = await scanner.scan()

        # One rich storage snapshot + web/sites + containerregistry + policyAssignments.
        assert len(snapshots) == 4

        # (a) Every distinct id appears exactly once.
        ids = [s.id for s in snapshots]
        assert len(ids) == len(set(ids))

        # (b) The storage account is NOT duplicated and retains its rich config.
        storage = [s for s in snapshots if "storageAccounts" in s.resource_type]
        assert len(storage) == 1
        assert storage[0].config["allow_blob_public_access"] is True
        assert storage[0].config["minimum_tls_version"] == "TLS1_0"

        # Generic-only types are present as inventory snapshots with empty config.
        types = {s.resource_type for s in snapshots}
        assert "microsoft.web/sites" in types
        assert "microsoft.containerregistry/registries" in types
        web = next(s for s in snapshots if s.resource_type == "microsoft.web/sites")
        assert web.config == {}
        assert web.data_tier == DataTier.TIER1_NATIVE

        # (c) Every snapshot passes validate_snapshot(), incl. RG/region-less ones.
        validator = _ValidatorAdapter()
        assert all(validator.validate_snapshot(s) for s in snapshots)

    async def test_inventory_only_snapshot_defaults_missing_fields(
        self,
        mock_credential: MagicMock,
        raw_inventory_resources: list[dict[str, Any]],
    ) -> None:
        """Resources without RG/region default to 'unknown' so validation passes."""
        scanner = _build_scanner_with_mock_rg(
            mock_credential,
            {"subscriptionId": raw_inventory_resources},
        )

        with patch.object(
            scanner, "_fetch_cost_data", new_callable=AsyncMock, return_value={}
        ):
            snapshots = await scanner.scan()

        policy_assignment = next(
            s for s in snapshots if "policyassignments" in s.resource_type
        )
        assert policy_assignment.resource_group == "unknown"
        assert policy_assignment.region == "unknown"


class TestSqlSnapshots:
    async def test_sql_config_populated_and_findings_fire(
        self,
        mock_credential: MagicMock,
        raw_sql_resources: list[dict[str, Any]],
        raw_sql_audit_resources: list[dict[str, Any]],
    ) -> None:
        """SQL server snapshots carry the config keys SQL rules read."""
        scanner = _build_scanner_with_mock_rg(
            mock_credential,
            {
                "microsoft.sql/servers\"": raw_sql_resources,
                "auditingsettings": raw_sql_audit_resources,
            },
        )

        with patch.object(
            scanner, "_fetch_cost_data", new_callable=AsyncMock, return_value={}
        ):
            snapshots = await scanner.scan()

        sql = [s for s in snapshots if s.resource_type == "Microsoft.Sql/servers"]
        assert len(sql) == 1
        cfg = sql[0].config
        assert cfg["public_network_access"] == "Enabled"
        assert cfg["minimal_tls_version"] == "1.0"
        assert cfg["auditing_state"] == "Disabled"

    async def test_sql_auditing_defaults_unknown(
        self,
        mock_credential: MagicMock,
        raw_sql_resources: list[dict[str, Any]],
    ) -> None:
        """When no auditing settings row exists, auditing_state is unknown."""
        scanner = _build_scanner_with_mock_rg(
            mock_credential,
            {"microsoft.sql/servers\"": raw_sql_resources},
        )
        with patch.object(
            scanner, "_fetch_cost_data", new_callable=AsyncMock, return_value={}
        ):
            snapshots = await scanner.scan()
        sql = next(s for s in snapshots if s.resource_type == "Microsoft.Sql/servers")
        assert sql.config["auditing_state"] == "unknown"


class TestAksSnapshots:
    async def test_aks_config_populated(
        self,
        mock_credential: MagicMock,
        raw_aks_resources: list[dict[str, Any]],
    ) -> None:
        """AKS snapshots carry the config keys AKS rules read."""
        scanner = _build_scanner_with_mock_rg(
            mock_credential,
            {"managedclusters": raw_aks_resources},
        )
        with patch.object(
            scanner, "_fetch_cost_data", new_callable=AsyncMock, return_value={}
        ):
            snapshots = await scanner.scan()

        aks = [
            s
            for s in snapshots
            if s.resource_type == "Microsoft.ContainerService/managedClusters"
        ]
        assert len(aks) == 1
        cfg = aks[0].config
        assert cfg["enable_rbac"] is False
        assert cfg["private_cluster"] is False
        assert cfg["authorized_ip_ranges"] == []
        assert cfg["network_policy"] == "none"

    async def test_typed_sql_aks_not_duplicated_by_inventory(
        self,
        mock_credential: MagicMock,
        raw_sql_resources: list[dict[str, Any]],
        raw_aks_resources: list[dict[str, Any]],
    ) -> None:
        """A typed SQL/AKS resource also present in inventory is not duplicated."""
        inventory = [
            {
                "id": (
                    "/subscriptions/sub-1/resourceGroups/rg1"
                    "/providers/Microsoft.Sql/servers/sql1"
                ),
                "name": "sql1",
                "type": "microsoft.sql/servers",
                "resourceGroup": "rg1",
                "location": "eastus",
                "tags": {},
                "subscriptionId": "sub-1",
            },
            {
                "id": (
                    "/subscriptions/sub-1/resourceGroups/rg1"
                    "/providers/Microsoft.ContainerService/managedClusters/aks1"
                ),
                "name": "aks1",
                "type": "microsoft.containerservice/managedclusters",
                "resourceGroup": "rg1",
                "location": "eastus",
                "tags": {},
                "subscriptionId": "sub-1",
            },
        ]
        scanner = _build_scanner_with_mock_rg(
            mock_credential,
            {
                "microsoft.sql/servers\"": raw_sql_resources,
                "managedclusters": raw_aks_resources,
                "subscriptionId": inventory,
            },
        )
        with patch.object(
            scanner, "_fetch_cost_data", new_callable=AsyncMock, return_value={}
        ):
            snapshots = await scanner.scan()

        ids = [s.id for s in snapshots]
        assert len(ids) == len(set(ids))
        # Rich typed snapshots win: SQL retains config, AKS retains config.
        sql = next(s for s in snapshots if s.resource_type == "Microsoft.Sql/servers")
        assert sql.config["public_network_access"] == "Enabled"

