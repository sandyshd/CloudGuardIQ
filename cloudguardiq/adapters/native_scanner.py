"""CloudGuardIQ - NativeScanner: orchestrates Resource Graph queries and rule evaluation.

The NativeScanner fetches Azure resources via Azure Resource Graph, normalises
them into `ResourceSnapshot` objects (all TIER1_NATIVE), optionally enriches
with cost data, and exposes a RULE_REGISTRY of all PolicyRule instances.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from functools import partial
from typing import Any, Protocol

from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.mgmt.costmanagement import CostManagementClient
from azure.mgmt.costmanagement.models import (
    ExportType,
    QueryAggregation,
    QueryDataset,
    QueryDefinition,
    QueryGrouping,
    QueryTimePeriod,
    TimeframeType,
)
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import (
    QueryRequest,
    QueryRequestOptions,
)

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
from cloudguardiq.adapters.rules.azure.monitor import (
    ActivityLogAlertsMissingRule,
    LogProfileRetentionRule,
)
from cloudguardiq.adapters.rules.azure.network import (
    AnyPortOpenToInternetRule,
    DDoSProtectionRule,
    InboundAllowAllRule,
    NSGFlowLogsRule,
    RDPOpenToInternetRule,
    SSHOpenToInternetRule,
)
from cloudguardiq.adapters.rules.azure.sql import (
    SqlAuditingDisabledRule,
    SqlMinTlsVersionRule,
    SqlPublicNetworkAccessRule,
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
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Backward-compatible ScannerRule protocol (legacy)
# ---------------------------------------------------------------------------


class ScannerRule(Protocol):
    """Protocol for native scanner rules."""

    rule_id: str
    resource_types: list[str]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate a 55apshot and return any findings."""
        ...


# ---------------------------------------------------------------------------
# Rule registry — all 44 PolicyRule instances
# ---------------------------------------------------------------------------

RULE_REGISTRY = [
    # Storage (STOR-001 .. STOR-010)
    PublicBlobAccessRule(),
    HttpTrafficAllowedRule(),
    MinTlsVersionRule(),
    SharedKeyAuthRule(),
    NetworkDefaultActionRule(),
    BlobSoftDeleteRule(),
    BlobVersioningRule(),
    InfrastructureEncryptionRule(),
    DiagnosticLoggingRule(),
    LifecycleManagementRule(),
    # Network (NET-001 .. NET-006)
    SSHOpenToInternetRule(),
    RDPOpenToInternetRule(),
    AnyPortOpenToInternetRule(),
    NSGFlowLogsRule(),
    InboundAllowAllRule(),
    DDoSProtectionRule(),
    # IAM (IAM-001 .. IAM-008)
    OwnerRoleDirectUserRule(),
    OwnerRoleSubscriptionScopeRule(),
    SPOwnerMultipleSubscriptionsRule(),
    GuestPrivilegedRoleRule(),
    ClassicAdminRoleRule(),
    NoMFAConditionalAccessRule(),
    ExternalUserPrivilegedRoleRule(),
    SPPasswordExpiryRule(),
    # Compute (COMP-001 .. COMP-007)
    OSDiskEncryptionRule(),
    UnmanagedDiskRule(),
    NoBackupPolicyRule(),
    PublicIPDirectAttachedRule(),
    OutdatedOSImageRule(),
    MissingCostTagsRule(),
    IdleVMRule(),
    # Key Vault (KV-001 .. KV-005)
    SoftDeleteRule(),
    PurgeProtectionRule(),
    PublicNetworkAccessRule(),
    NoDiagnosticLoggingRule(),
    SecretNoExpiryRule(),
    # FinOps (FIN-001 .. FIN-008)
    UnattachedManagedDiskRule(),
    UnassignedPublicIPRule(),
    EmptyLoadBalancerRule(),
    HotTierBlobNotAccessedRule(),
    OversizedVMRule(),
    DevTestOutsideBusinessHoursRule(),
    AppGatewayLowUtilisationRule(),
    AKSNoAutoscalerRule(),
    # SQL / PostgreSQL (SQL-001 .. SQL-003)
    SqlPublicNetworkAccessRule(),
    SqlMinTlsVersionRule(),
    SqlAuditingDisabledRule(),
    # App Service (APP-001 .. APP-003)
    AppServiceHttpsOnlyRule(),
    AppServiceMinTlsRule(),
    AppServiceAuthDisabledRule(),
    # AKS (AKS-001 .. AKS-003)
    AKSRBACDisabledRule(),
    AKSPublicApiServerRule(),
    AKSNetworkPolicyMissingRule(),
    # Monitor (MON-001 .. MON-002)
    ActivityLogAlertsMissingRule(),
    LogProfileRetentionRule(),
]

# ---------------------------------------------------------------------------
# Resource Graph KQL queries
# ---------------------------------------------------------------------------

_STORAGE_QUERY = """
Resources
| where type == "microsoft.storage/storageaccounts"
| project id, name, resourceGroup, location, tags,
    properties.allowBlobPublicAccess,
    properties.minimumTlsVersion,
    properties.networkAcls.defaultAction,
    properties.supportsHttpsTrafficOnly,
    properties.allowSharedKeyAccess,
    properties.encryption.requireInfrastructureEncryption
""".strip()

_NSG_QUERY = """
Resources
| where type == "microsoft.network/networksecuritygroups"
| project id, name, resourceGroup, location, tags,
    properties.securityRules,
    properties.defaultSecurityRules
""".strip()

_VM_QUERY = """
Resources
| where type == "microsoft.compute/virtualmachines"
| project id, name, resourceGroup, location, tags,
    properties.storageProfile.osDisk.managedDisk,
    properties.storageProfile.osDisk.encryptionSettings,
    properties.networkProfile.networkInterfaces
""".strip()

_KV_QUERY = """
Resources
| where type == "microsoft.keyvault/vaults"
| project id, name, resourceGroup, location, tags,
    properties.enableSoftDelete,
    properties.enablePurgeProtection,
    properties.publicNetworkAccess
""".strip()

_INVENTORY_QUERY = """
Resources
| project id, name, type, resourceGroup, location, tags, subscriptionId
""".strip()

_SQL_QUERY = """
Resources
| where type == "microsoft.sql/servers"
| project id, name, resourceGroup, location, tags,
    properties.publicNetworkAccess,
    properties.minimalTlsVersion
""".strip()

_SQL_AUDIT_QUERY = """
Resources
| where type == "microsoft.sql/servers/auditingsettings"
| project id, name, properties.state
""".strip()

_AKS_QUERY = """
Resources
| where type == "microsoft.containerservice/managedclusters"
| project id, name, resourceGroup, location, tags,
    properties.enableRBAC,
    properties.apiServerAccessProfile.enablePrivateCluster,
    properties.apiServerAccessProfile.authorizedIPRanges,
    properties.networkProfile.networkPolicy
""".strip()

_APPSERVICE_QUERY = """
Resources
| where type == "microsoft.web/sites"
| project id, name, resourceGroup, location, tags,
    properties.httpsOnly,
    properties.clientCertEnabled,
    properties.siteConfig.minTlsVersion
""".strip()

_ACTIVITY_ALERT_QUERY = """
Resources
| where type == "microsoft.insights/activitylogalerts"
| project id, name, resourceGroup, location, tags,
    properties.condition
""".strip()

_LOG_PROFILE_QUERY = """
Resources
| where type == "microsoft.insights/logprofiles"
| project id, name, resourceGroup, location, tags,
    properties.retentionPolicy.days
""".strip()

_DISK_QUERY = """
Resources
| where type == "microsoft.compute/disks"
| project id, name, resourceGroup, location, tags,
    properties.diskState
""".strip()

_PUBLIC_IP_QUERY = """
Resources
| where type == "microsoft.network/publicipaddresses"
| project id, name, resourceGroup, location, tags,
    properties.ipConfiguration
""".strip()

_LOAD_BALANCER_QUERY = """
Resources
| where type == "microsoft.network/loadbalancers"
| project id, name, resourceGroup, location, tags,
    properties.backendAddressPools
""".strip()


_ROLE_ASSIGNMENT_QUERY = """
authorizationresources
| where type == "microsoft.authorization/roleassignments"
| project id, name,
    properties.roleDefinitionId,
    properties.principalId,
    properties.principalType,
    properties.scope
""".strip()


class NativeScanner:
    """Orchestrates Azure Resource Graph queries, snapshot normalisation, and rule evaluation.

    Args:
        credential: An Azure `TokenCredential` for authenticating API calls.
        subscription_id: The Azure subscription to scan.
    """

    def __init__(
        self,
        credential: TokenCredential | None = None,
        subscription_id: str = '',
    ) -> None:
        self._credential = credential
        self._subscription_id = subscription_id
        self._rg_client = ResourceGraphClient(credential) if credential else None
        self._rules = list(RULE_REGISTRY)

    def register(self, rule: ScannerRule) -> None:
        """Register a scanner rule (legacy API)."""
        self._rules.append(rule)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self) -> list[ResourceSnapshot]:
        """Fetch resources from Resource Graph and return normalised snapshots.

        Queries for storage accounts, NSGs, VMs, and Key Vaults in parallel,
        normalises the raw JSON into `ResourceSnapshot` objects with
        `data_tier=TIER1_NATIVE`, and optionally enriches with cost data.
        """
        storage_task = self._query_resource_graph(_STORAGE_QUERY)
        nsg_task = self._query_resource_graph(_NSG_QUERY)
        vm_task = self._query_resource_graph(_VM_QUERY)
        kv_task = self._query_resource_graph(_KV_QUERY)
        sql_task = self._query_resource_graph(_SQL_QUERY)
        sql_audit_task = self._query_resource_graph(_SQL_AUDIT_QUERY)
        aks_task = self._query_resource_graph(_AKS_QUERY)
        appservice_task = self._query_resource_graph(_APPSERVICE_QUERY)
        activity_alert_task = self._query_resource_graph(_ACTIVITY_ALERT_QUERY)
        log_profile_task = self._query_resource_graph(_LOG_PROFILE_QUERY)
        disk_task = self._query_resource_graph(_DISK_QUERY)
        public_ip_task = self._query_resource_graph(_PUBLIC_IP_QUERY)
        load_balancer_task = self._query_resource_graph(_LOAD_BALANCER_QUERY)
        role_assignment_task = self._query_resource_graph(_ROLE_ASSIGNMENT_QUERY)
        inventory_task = self._query_resource_graph(_INVENTORY_QUERY)

        (
            raw_storage,
            raw_nsg,
            raw_vm,
            raw_kv,
            raw_sql,
            raw_sql_audit,
            raw_aks,
            raw_appservice,
            raw_activity_alert,
            raw_log_profile,
            raw_disk,
            raw_public_ip,
            raw_load_balancer,
            raw_role_assignment,
            raw_inventory,
        ) = await asyncio.gather(
            storage_task,
            nsg_task,
            vm_task,
            kv_task,
            sql_task,
            sql_audit_task,
            aks_task,
            appservice_task,
            activity_alert_task,
            log_profile_task,
            disk_task,
            public_ip_task,
            load_balancer_task,
            role_assignment_task,
            inventory_task,
        )

        snapshots_lists = await asyncio.gather(
            self._build_storage_snapshots(raw_storage),
            self._build_nsg_snapshots(raw_nsg),
            self._build_vm_snapshots(raw_vm),
            self._build_keyvault_snapshots(raw_kv),
            self._build_sql_snapshots(raw_sql, raw_sql_audit),
            self._build_aks_snapshots(raw_aks),
            self._build_appservice_snapshots(raw_appservice),
            self._build_activity_alert_snapshots(raw_activity_alert),
            self._build_log_profile_snapshots(raw_log_profile),
            self._build_disk_snapshots(raw_disk),
            self._build_public_ip_snapshots(raw_public_ip),
            self._build_load_balancer_snapshots(raw_load_balancer),
            self._build_role_assignment_snapshots(raw_role_assignment),
        )

        # Rich typed snapshots take precedence; track their IDs for dedup.
        snapshots: list[ResourceSnapshot] = []
        seen_ids: set[str] = set()
        for s_list in snapshots_lists:
            for snap in s_list:
                snapshots.append(snap)
                seen_ids.add(snap.id)

        # Merge generic inventory snapshots for every other resource type,
        # skipping any resource already captured by a typed builder.
        generic_snapshots = await self._build_generic_snapshots(raw_inventory)
        for snap in generic_snapshots:
            if snap.id not in seen_ids:
                snapshots.append(snap)
                seen_ids.add(snap.id)

        # Best-effort cost enrichment
        resource_ids = [s.id for s in snapshots]
        cost_map = await self._fetch_cost_data(resource_ids)
        for snap in snapshots:
            if snap.id in cost_map:
                snap.cost_monthly = cost_map[snap.id]

        return snapshots

    # ------------------------------------------------------------------
    # Resource Graph helpers
    # ------------------------------------------------------------------

    async def _query_resource_graph(self, query: str) -> list[dict[str, Any]]:
        """Execute a KQL query against Azure Resource Graph with pagination."""
        loop = asyncio.get_running_loop()
        results: list[dict[str, Any]] = []
        skip_token: str | None = None

        while True:
            options = QueryRequestOptions(
                result_format="objectArray",
                skip_token=skip_token,
            )
            request = QueryRequest(
                subscriptions=[self._subscription_id],
                query=query,
                options=options,
            )
            try:
                assert self._rg_client is not None
                assert self._rg_client is not None
                response = await loop.run_in_executor(
                    None, partial(self._rg_client.resources, request),
                )
            except Exception:
                logger.exception("Resource Graph query failed: %s", query[:80])
                return results

            if isinstance(response.data, list):
                results.extend(response.data)

            skip_token = getattr(response, "skip_token", None)
            if not skip_token:
                break

        logger.info(
            "Resource Graph returned %d results for query: %s",
            len(results),
            query[:60],
        )
        return results

    # ------------------------------------------------------------------
    # Snapshot builders
    # ------------------------------------------------------------------

    async def _build_storage_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise raw Resource Graph storage account JSON into ResourceSnapshot objects."""
        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            props = r.get("properties", r)
            config: dict[str, Any] = {
                "allow_blob_public_access":  _coalesce(
                    _get_nested(r, "properties_allowBlobPublicAccess"),
                    _get_nested(props, "allowBlobPublicAccess"),
                ),
                "minimum_tls_version":  _coalesce(
                    _get_nested(r, "properties_minimumTlsVersion"),
                    _get_nested(props, "minimumTlsVersion"),
                ),
                "network_default_action":  _coalesce(
                    _get_nested(r, "properties_networkAcls_defaultAction"),
                    _get_nested(props, "networkAcls", "defaultAction"),
                ),
                "enable_https_traffic_only":  _coalesce(
                    _get_nested(r, "properties_supportsHttpsTrafficOnly"),
                    _get_nested(props, "supportsHttpsTrafficOnly"),
                ),
                "allow_shared_key_access":  _coalesce(
                    _get_nested(r, "properties_allowSharedKeyAccess"),
                    _get_nested(props, "allowSharedKeyAccess"),
                ),
                "infrastructure_encryption_enabled":  _coalesce(
                    _get_nested(r, "properties_encryption_requireInfrastructureEncryption"),
                    _get_nested(props, "encryption", "requireInfrastructureEncryption"),
                ),
            }
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group=r.get("resourceGroup", ""),
                    resource_type="Microsoft.Storage/storageAccounts",
                    resource_name=r.get("name", ""),
                    region=r.get("location", ""),
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_nsg_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise NSG resources. Flatten security rules into config."""
        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            props = r.get("properties", r)
            security_rules = (
                _coalesce(
                    _get_nested(r, "properties_securityRules"),
                    _get_nested(props, "securityRules"),
                )
                or []
            )
            default_rules = (
                _coalesce(
                    _get_nested(r, "properties_defaultSecurityRules"),
                    _get_nested(props, "defaultSecurityRules"),
                )
                or []
            )
            # Flatten rule properties for evaluation
            flat_rules: list[dict[str, Any]] = []
            for rule in security_rules:
                rule_props = rule.get("properties", rule)
                flat_rules.append({
                    "name": rule.get("name", ""),
                    "access": rule_props.get("access", ""),
                    "direction": rule_props.get("direction", ""),
                    "sourceAddressPrefix": rule_props.get("sourceAddressPrefix", ""),
                    "destinationPortRange": rule_props.get("destinationPortRange", ""),
                    "protocol": rule_props.get("protocol", ""),
                    "priority": rule_props.get("priority", 0),
                })

            config: dict[str, Any] = {
                "securityRules": flat_rules,
                "defaultSecurityRules": default_rules,
            }
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group=r.get("resourceGroup", ""),
                    resource_type="Microsoft.Network/networkSecurityGroups",
                    resource_name=r.get("name", ""),
                    region=r.get("location", ""),
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_vm_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise VM resources. Include disk encryption state."""
        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            props = r.get("properties", r)
            managed_disk = (
                _coalesce(
                    _get_nested(r, "properties_storageProfile_osDisk_managedDisk"),
                    _get_nested(props, "storageProfile", "osDisk", "managedDisk"),
                )
            )
            encryption_settings = (
                _coalesce(
                    _get_nested(r, "properties_storageProfile_osDisk_encryptionSettings"),
                    _get_nested(props, "storageProfile", "osDisk", "encryptionSettings"),
                )
            )
            network_interfaces = (
                _coalesce(
                    _get_nested(r, "properties_networkProfile_networkInterfaces"),
                    _get_nested(props, "networkProfile", "networkInterfaces"),
                )
                or []
            )

            encryption_enabled = False
            if encryption_settings:
                encryption_enabled = bool(
                    encryption_settings.get("enabled")
                    if isinstance(encryption_settings, dict)
                    else encryption_settings
                )

            config: dict[str, Any] = {
                "managedDisk": managed_disk,
                "encryptionAtHost": encryption_enabled,
                "encryptionSettings": encryption_settings,
                "networkInterfaces": network_interfaces,
                "osDiskIsManaged": managed_disk is not None,
            }
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group=r.get("resourceGroup", ""),
                    resource_type="Microsoft.Compute/virtualMachines",
                    resource_name=r.get("name", ""),
                    region=r.get("location", ""),
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_keyvault_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise Key Vault resources."""
        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            props = r.get("properties", r)
            config: dict[str, Any] = {
                "enableSoftDelete":  _coalesce(
                    _get_nested(r, "properties_enableSoftDelete"),
                    _get_nested(props, "enableSoftDelete"),
                ),
                "enablePurgeProtection":  _coalesce(
                    _get_nested(r, "properties_enablePurgeProtection"),
                    _get_nested(props, "enablePurgeProtection"),
                ),
                "publicNetworkAccess":  _coalesce(
                    _get_nested(r, "properties_publicNetworkAccess"),
                    _get_nested(props, "publicNetworkAccess"),
                )
            }
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group=r.get("resourceGroup", ""),
                    resource_type="Microsoft.KeyVault/vaults",
                    resource_name=r.get("name", ""),
                    region=r.get("location", ""),
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_sql_snapshots(
        self,
        raw_resources: list[dict[str, Any]],
        raw_audit_settings: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise SQL server resources into ResourceSnapshot objects.

        Auditing state lives on the ``auditingSettings/Default`` child
        resource, so it is fetched separately and joined back to its parent
        server by ARM resource id. Servers without a matching auditing row
        report ``"unknown"`` rather than a (potentially false) ``"disabled"``.

        Args:
            raw_resources: Raw Resource Graph rows for ``microsoft.sql/servers``.
            raw_audit_settings: Raw rows for ``.../auditingsettings`` children.

        Returns:
            A list of ``TIER1_NATIVE`` SQL server snapshots.
        """
        audit_map: dict[str, str] = {}
        for a in raw_audit_settings:
            audit_id = str(a.get("id", "")).lower()
            parent_id = audit_id.split("/auditingsettings", 1)[0]
            state = _coalesce(
                _get_nested(a, "properties_state"),
                _get_nested(a.get("properties", {}), "state"),
            )
            if parent_id and state is not None:
                audit_map[parent_id] = str(state)

        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            props = r.get("properties", r)
            server_id = str(r.get("id", "")).lower()
            config: dict[str, Any] = {
                "public_network_access": _coalesce(
                    _get_nested(r, "properties_publicNetworkAccess"),
                    _get_nested(props, "publicNetworkAccess"),
                ),
                "minimal_tls_version": _coalesce(
                    _get_nested(r, "properties_minimalTlsVersion"),
                    _get_nested(props, "minimalTlsVersion"),
                ),
                "auditing_state": audit_map.get(server_id, "unknown"),
            }
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group=r.get("resourceGroup", ""),
                    resource_type="Microsoft.Sql/servers",
                    resource_name=r.get("name", ""),
                    region=r.get("location", ""),
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_aks_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise AKS managed cluster resources into ResourceSnapshot objects.

        All fields the AKS rules read (RBAC, private cluster, authorized IP
        ranges, network policy) are top-level on the cluster, so a single
        Resource Graph query is sufficient.

        Args:
            raw_resources: Raw rows for ``microsoft.containerservice/managedclusters``.

        Returns:
            A list of ``TIER1_NATIVE`` AKS cluster snapshots.
        """
        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            props = r.get("properties", r)
            config: dict[str, Any] = {
                "enable_rbac": _coalesce(
                    _get_nested(r, "properties_enableRBAC"),
                    _get_nested(props, "enableRBAC"),
                ),
                "private_cluster": bool(
                    _coalesce(
                        _get_nested(
                            r,
                            "properties_apiServerAccessProfile_enablePrivateCluster",
                        ),
                        _get_nested(
                            props,
                            "apiServerAccessProfile",
                            "enablePrivateCluster",
                        ),
                    )
                ),
                "authorized_ip_ranges": _coalesce(
                    _get_nested(
                        r,
                        "properties_apiServerAccessProfile_authorizedIPRanges",
                    ),
                    _get_nested(
                        props, "apiServerAccessProfile", "authorizedIPRanges",
                    ),
                )
                or [],
                "network_policy": _coalesce(
                    _get_nested(r, "properties_networkProfile_networkPolicy"),
                    _get_nested(props, "networkProfile", "networkPolicy"),
                )
                or "",
            }
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group=r.get("resourceGroup", ""),
                    resource_type="Microsoft.ContainerService/managedClusters",
                    resource_name=r.get("name", ""),
                    region=r.get("location", ""),
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_appservice_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise App Service (Microsoft.Web/sites) resources.

        ``https_only``, ``client_cert_enabled`` and ``min_tls_version`` are
        derivable from Resource Graph. ``auth_enabled`` lives in the
        ``authsettings`` child resource which Resource Graph does not expose;
        it is best-effort read from the site properties and defaults to
        ``False`` so APP-003 evaluates against a known-safe baseline.

        Args:
            raw_resources: Raw rows for ``microsoft.web/sites``.

        Returns:
            A list of ``TIER1_NATIVE`` App Service snapshots.
        """
        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            props = r.get("properties", r)
            config: dict[str, Any] = {
                "https_only": _coalesce(
                    _get_nested(r, "properties_httpsOnly"),
                    _get_nested(props, "httpsOnly"),
                ),
                "client_cert_enabled": _coalesce(
                    _get_nested(r, "properties_clientCertEnabled"),
                    _get_nested(props, "clientCertEnabled"),
                ),
                "min_tls_version": _coalesce(
                    _get_nested(r, "properties_siteConfig_minTlsVersion"),
                    _get_nested(props, "siteConfig", "minTlsVersion"),
                ),
                "auth_enabled": bool(
                    _coalesce(
                        _get_nested(r, "properties_siteAuthEnabled"),
                        _get_nested(props, "siteAuthEnabled"),
                    )
                ),
            }
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group=r.get("resourceGroup", ""),
                    resource_type="Microsoft.Web/sites",
                    resource_name=r.get("name", ""),
                    region=r.get("location", ""),
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_activity_alert_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise activity log alert resources into ResourceSnapshot objects.

        The set of monitored operations is extracted from the alert condition
        (``condition.allOf[].equals`` where ``field == "operationName"``) so
        MON-001 can compare it against the required critical operations.

        Args:
            raw_resources: Raw rows for ``microsoft.insights/activitylogalerts``.

        Returns:
            A list of ``TIER1_NATIVE`` activity log alert snapshots.
        """
        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            props = r.get("properties", r)
            condition = _coalesce(
                _get_nested(r, "properties_condition"),
                _get_nested(props, "condition"),
            )
            operations: list[str] = []
            all_of = (condition or {}).get("allOf", []) if isinstance(condition, dict) else []
            for clause in all_of:
                if not isinstance(clause, dict):
                    continue
                if clause.get("field") == "operationName" and clause.get("equals"):
                    operations.append(str(clause["equals"]))
            config: dict[str, Any] = {"monitored_operations": operations}
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group=r.get("resourceGroup", "") or "unknown",
                    resource_type="Microsoft.Insights/activityLogAlerts",
                    resource_name=r.get("name", ""),
                    region=r.get("location", "") or "global",
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_log_profile_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise log profile resources into ResourceSnapshot objects.

        Log profiles are subscription-scoped (no resource group), so the
        resource group defaults to ``"unknown"`` to satisfy snapshot
        validation. ``retention_days`` drives MON-002.

        Args:
            raw_resources: Raw rows for ``microsoft.insights/logprofiles``.

        Returns:
            A list of ``TIER1_NATIVE`` log profile snapshots.
        """
        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            props = r.get("properties", r)
            config: dict[str, Any] = {
                "retention_days": _coalesce(
                    _get_nested(r, "properties_retentionPolicy_days"),
                    _get_nested(props, "retentionPolicy", "days"),
                )
                or 0,
            }
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group=r.get("resourceGroup", "") or "unknown",
                    resource_type="Microsoft.Insights/logProfiles",
                    resource_name=r.get("name", ""),
                    region=r.get("location", "") or "global",
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_disk_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise managed disk resources into ResourceSnapshot objects.

        ``disk_state`` drives FIN-001 (which additionally requires a non-zero
        monthly cost supplied by cost enrichment).

        Args:
            raw_resources: Raw rows for ``microsoft.compute/disks``.

        Returns:
            A list of ``TIER1_NATIVE`` managed disk snapshots.
        """
        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            props = r.get("properties", r)
            config: dict[str, Any] = {
                "disk_state": _coalesce(
                    _get_nested(r, "properties_diskState"),
                    _get_nested(props, "diskState"),
                ),
            }
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group=r.get("resourceGroup", ""),
                    resource_type="Microsoft.Compute/disks",
                    resource_name=r.get("name", ""),
                    region=r.get("location", ""),
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_public_ip_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise public IP resources into ResourceSnapshot objects.

        ``ip_association`` is the id of the IP configuration the address is
        attached to, or ``None`` when the address is reserved but unassigned
        (which FIN-002 flags as waste).

        Args:
            raw_resources: Raw rows for ``microsoft.network/publicipaddresses``.

        Returns:
            A list of ``TIER1_NATIVE`` public IP snapshots.
        """
        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            props = r.get("properties", r)
            ip_config = _coalesce(
                _get_nested(r, "properties_ipConfiguration"),
                _get_nested(props, "ipConfiguration"),
            )
            association: Any = None
            if isinstance(ip_config, dict):
                association = ip_config.get("id")
            elif ip_config:
                association = ip_config
            config: dict[str, Any] = {"ip_association": association}
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group=r.get("resourceGroup", ""),
                    resource_type="Microsoft.Network/publicIPAddresses",
                    resource_name=r.get("name", ""),
                    region=r.get("location", ""),
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_load_balancer_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise load balancer resources into ResourceSnapshot objects.

        ``backend_pool_count`` is the number of backend address pools; FIN-003
        flags balancers with zero pools and a non-zero monthly cost.

        Args:
            raw_resources: Raw rows for ``microsoft.network/loadbalancers``.

        Returns:
            A list of ``TIER1_NATIVE`` load balancer snapshots.
        """
        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            props = r.get("properties", r)
            pools = (
                _coalesce(
                    _get_nested(r, "properties_backendAddressPools"),
                    _get_nested(props, "backendAddressPools"),
                )
                or []
            )
            config: dict[str, Any] = {
                "backend_pool_count": len(pools) if isinstance(pools, list) else 0,
            }
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group=r.get("resourceGroup", ""),
                    resource_type="Microsoft.Network/loadBalancers",
                    resource_name=r.get("name", ""),
                    region=r.get("location", ""),
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_role_assignment_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise Azure role assignments into ResourceSnapshot objects.

        Sources rows from the Resource Graph ``authorizationresources`` table and
        maps the built-in ``roleDefinitionId`` GUID to a human-readable role name
        so the IAM rules (IAM-001/002/003) can evaluate ``role_definition_name``,
        ``principal_type``, ``scope`` and ``owner_subscription_count``.

        Args:
            raw_resources: Raw rows for ``microsoft.authorization/roleassignments``.

        Returns:
            A list of ``TIER1_NATIVE`` role-assignment snapshots.
        """
        # Well-known Azure built-in role definition GUIDs.
        builtin_roles = {
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
            "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
            "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
            "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
        }

        def _sub_id(scope: str) -> str:
            parts = scope.split("/")
            if len(parts) >= 3 and parts[1].lower() == "subscriptions":
                return parts[2]
            return ""

        # First pass: extract normalised fields per row.
        rows: list[dict[str, Any]] = []
        for r in raw_resources:
            props = r.get("properties", r)
            role_def_id = str(
                _coalesce(
                    _get_nested(r, "properties_roleDefinitionId"),
                    _get_nested(props, "roleDefinitionId"),
                )
                or ""
            )
            role_guid = role_def_id.rsplit("/", 1)[-1].lower()
            role_name = builtin_roles.get(role_guid, role_guid)
            principal_type = str(
                _coalesce(
                    _get_nested(r, "properties_principalType"),
                    _get_nested(props, "principalType"),
                )
                or ""
            )
            principal_id = str(
                _coalesce(
                    _get_nested(r, "properties_principalId"),
                    _get_nested(props, "principalId"),
                )
                or ""
            )
            scope = str(
                _coalesce(
                    _get_nested(r, "properties_scope"),
                    _get_nested(props, "scope"),
                )
                or ""
            )
            rows.append(
                {
                    "raw": r,
                    "role_name": role_name,
                    "principal_type": principal_type,
                    "principal_id": principal_id,
                    "scope": scope,
                }
            )

        # Second pass: count distinct subscriptions where each principal is Owner.
        owner_subs: dict[str, set[str]] = {}
        for row in rows:
            if row["role_name"] == "Owner" and row["principal_id"]:
                sub = _sub_id(row["scope"])
                if sub:
                    owner_subs.setdefault(row["principal_id"], set()).add(sub)

        snapshots: list[ResourceSnapshot] = []
        for row in rows:
            r = row["raw"]
            owner_count = len(owner_subs.get(row["principal_id"], set()))
            config: dict[str, Any] = {
                "role_definition_name": row["role_name"],
                "principal_type": row["principal_type"],
                "scope": row["scope"],
                "owner_subscription_count": owner_count,
            }
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group="unknown",
                    resource_type="Microsoft.Authorization/roleAssignments",
                    resource_name=r.get("name", ""),
                    region="global",
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config=config,
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

    async def _build_generic_snapshots(
        self, raw_resources: list[dict[str, Any]],
    ) -> list[ResourceSnapshot]:
        """Normalise generic Resource Graph inventory rows into ResourceSnapshot objects.

        Every resource type in the subscription is captured as a lightweight
        inventory snapshot with an empty ``config``. These snapshots exist for
        inventory completeness only -- policy rules still fire exclusively on the
        types they understand. Resources that are subscription-scoped and have no
        resource group or region default those fields to ``"unknown"`` so that
        ``AdapterBase.validate_snapshot`` does not reject them.

        Args:
            raw_resources: Raw rows returned by the generic inventory KQL query.

        Returns:
            A list of ``TIER1_NATIVE`` inventory snapshots, one per row.
        """
        snapshots: list[ResourceSnapshot] = []
        for r in raw_resources:
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=r.get("subscriptionId") or self._subscription_id,
                    resource_group=r.get("resourceGroup") or "unknown",
                    resource_type=r.get("type") or "unknown",
                    resource_name=r.get("name") or "unknown",
                    region=r.get("location") or "unknown",
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config={},
                    tags=r.get("tags") or {},
                ),
            )
        return snapshots

        # ------------------------------------------------------------------
    # Cost enrichment
    # ------------------------------------------------------------------

    async def _run_cost_query_with_retry(
        self,
        loop: asyncio.AbstractEventLoop,
        call: Any,
        max_attempts: int = 5,
        base_delay: float = 2.0,
        max_delay: float = 60.0,
    ) -> Any:
        """Invoke the Cost Management query with exponential backoff on 429s.

        Azure Cost Management enforces strict per-subscription rate limits.
        When a 429 is returned, we honor the ``Retry-After`` header if
        present, otherwise apply exponential backoff capped at ``max_delay``.
        Non-throttling errors propagate immediately to the outer handler.
        """
        attempt = 0
        while True:
            attempt += 1
            try:
                return await loop.run_in_executor(None, call)
            except HttpResponseError as exc:
                status = getattr(exc, "status_code", None)
                if status != 429 or attempt >= max_attempts:
                    raise
                retry_after = base_delay * (2 ** (attempt - 1))
                response = getattr(exc, "response", None)
                headers = getattr(response, "headers", None) or {}
                header_value = headers.get("Retry-After") or headers.get("retry-after")
                if header_value:
                    with contextlib.suppress(TypeError, ValueError):
                        retry_after = float(header_value)
                retry_after = min(retry_after, max_delay)
                logger.warning(
                    "Cost Management API returned 429 (attempt %d/%d); retrying in %.1fs",
                    attempt, max_attempts, retry_after,
                )
                await asyncio.sleep(retry_after)

    async def _fetch_cost_data(
        self, resource_ids: list[str],
    ) -> dict[str, float]:
        """Call Azure Cost Management API to get monthly cost per resource.

        Returns a dict mapping resource_id to cost_usd.
        On any API error returns an empty dict - cost data is enrichment only.
        """
        if not resource_ids:
            return {}

        try:
            loop = asyncio.get_running_loop()
            assert self._credential is not None
            assert self._credential is not None
            client = CostManagementClient(self._credential)
            scope = f"/subscriptions/{self._subscription_id}"

            from datetime import datetime, timedelta, timezone

            now = datetime.now(timezone.utc)
            start = (now.replace(day=1) - timedelta(days=1)).replace(day=1)
            end = now

            query_def = QueryDefinition(
                type=ExportType.ACTUAL_COST,
                timeframe=TimeframeType.CUSTOM,
                time_period=QueryTimePeriod(from_property=start, to=end),
                dataset=QueryDataset(
                    granularity="None",
                    aggregation={
                        "totalCost": QueryAggregation(
                            name="Cost", function="Sum",
                        ),
                    },
                    grouping=[
                        QueryGrouping(
                            type="Dimension", name="ResourceId",
                        ),
                    ],
                ),
            )

            response = await self._run_cost_query_with_retry(
                loop, partial(client.query.usage, scope, query_def),
            )

            cost_map: dict[str, float] = {}
            if response and response.rows:
                for row in response.rows:
                    if len(row) >= 2:
                        rid = str(row[1]).lower()
                        cost = float(row[0])
                        cost_map[rid] = cost

            logger.info("Fetched cost data for %d resources", len(cost_map))
            return cost_map

        except Exception:
            logger.exception("Cost Management API call failed — continuing without cost data")
            return {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_nested(obj: dict[str, Any], *keys: str) -> Any:
    """Safely traverse nested dicts / underscore-flattened Resource Graph keys."""
    current: Any = obj
    for key in keys:
        if not isinstance(current, dict):
            return None
        # Resource Graph flattens nested keys with underscores in objectArray mode
        current = current.get(key)
        if current is None:
            return None
    return current


def _coalesce(*values: Any) -> Any:
    """Return the first non-None value, or None if all are None."""
    for v in values:
        if v is not None:
            return v
    return None
