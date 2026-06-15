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
        inventory_task = self._query_resource_graph(_INVENTORY_QUERY)

        raw_storage, raw_nsg, raw_vm, raw_kv, raw_inventory = await asyncio.gather(
            storage_task, nsg_task, vm_task, kv_task, inventory_task,
        )

        snapshots_lists = await asyncio.gather(
            self._build_storage_snapshots(raw_storage),
            self._build_nsg_snapshots(raw_nsg),
            self._build_vm_snapshots(raw_vm),
            self._build_keyvault_snapshots(raw_kv),
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
