"""CloudGuardIQ -- Cosmos DB repository (async).

Partition key mapping (must match Terraform container definitions):
  - findings:     /subscription_id
  - snapshots:    /provider
  - remediations: /finding_id
  - system:       /type
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from azure.cosmos.aio import ContainerProxy, CosmosClient, DatabaseProxy
from azure.identity.aio import DefaultAzureCredential

from cloudguardiq.adapters.base import CapabilityFlags
from cloudguardiq.core.config import Settings
from cloudguardiq.core.models import FindingResult, RemediationCard, ResourceSnapshot

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Query builders (pure functions for unit testing — no Cosmos dependency)
# ---------------------------------------------------------------------------


def _build_findings_query(
    tenant_id: str, subscription_id: str, limit: int = 50
) -> tuple[str, list[dict[str, object]]]:
    """Return (query, params) for listing findings within a tenant.

    The ``tenant_id`` filter is mandatory (Phase 1: tenant isolation). When
    ``tenant_id`` is an empty string, the query degrades to legacy behaviour
    (no tenant filter) so pre-backfill rows remain readable; once the
    backfill script runs, all rows have a tenant_id and callers must pass
    one.
    """
    params: list[dict[str, object]] = [
        {"name": "@limit", "value": limit},
        {"name": "@sub_id", "value": subscription_id},
        {"name": "@tenant_id", "value": tenant_id},
    ]
    if tenant_id:
        query = (
            "SELECT TOP @limit * FROM c "
            "WHERE c.tenant_id = @tenant_id "
            "AND c.subscription_id = @sub_id "
            "ORDER BY c.detected_at DESC"
        )
    else:
        query = (
            "SELECT TOP @limit * FROM c "
            "WHERE c.subscription_id = @sub_id "
            "ORDER BY c.detected_at DESC"
        )
    return query, params


def _build_finding_lookup_query(
    tenant_id: str, finding_id: str
) -> tuple[str, list[dict[str, object]]]:
    """Return (query, params) for a single-finding lookup scoped by tenant."""
    params: list[dict[str, object]] = [
        {"name": "@fid", "value": finding_id},
        {"name": "@tenant_id", "value": tenant_id},
    ]
    if tenant_id:
        query = (
            "SELECT * FROM c "
            "WHERE c.tenant_id = @tenant_id AND c.finding_id = @fid"
        )
    else:
        query = "SELECT * FROM c WHERE c.finding_id = @fid"
    return query, params


class CosmosRepository:
    """Async Cosmos DB repository for CloudGuardIQ entities."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: CosmosClient | None = None
        self._db: DatabaseProxy | None = None
        self._credential: DefaultAzureCredential | None = None

    async def connect(self) -> None:
        """Initialise the Cosmos client and database proxy using RBAC."""
        self._credential = DefaultAzureCredential()
        self._client = CosmosClient(
            url=self._settings.cosmos_endpoint,
            credential=self._credential,
        )
        self._db = self._client.get_database_client(self._settings.cosmos_database)
        logger.info("Connected to Cosmos DB: %s (RBAC auth)", self._settings.cosmos_database)

    async def close(self) -> None:
        """Close the Cosmos client and credential."""
        if self._client:
            await self._client.close()
            logger.info("Cosmos DB connection closed")
        if self._credential:
            await self._credential.close()

    # ------------------------------------------------------------------
    # Container helpers
    # ------------------------------------------------------------------

    def _snapshots_container(self) -> ContainerProxy:
        """Return the snapshots container proxy."""
        assert self._db is not None
        return self._db.get_container_client(self._settings.cosmos_container_snapshots)

    def _findings_container(self) -> ContainerProxy:
        """Return the findings container proxy."""
        assert self._db is not None
        return self._db.get_container_client(self._settings.cosmos_container_findings)

    def _remediations_container(self) -> ContainerProxy:
        """Return the remediations container proxy."""
        assert self._db is not None
        return self._db.get_container_client(self._settings.cosmos_container_remediations)

    def _system_container(self) -> ContainerProxy:
        """Return the system container proxy."""
        assert self._db is not None
        return self._db.get_container_client(self._settings.cosmos_container_system)

    # ------------------------------------------------------------------
    # Snapshot operations  (partition key: /provider)
    # ------------------------------------------------------------------

    async def save_snapshot(self, snapshot: ResourceSnapshot) -> str:
        """Persist a ResourceSnapshot. Returns the snapshot id."""
        doc = snapshot.model_dump(mode="json")
        # Root-level tenant_id for tenant-scoped queries (Phase 1 isolation)
        doc["tenant_id"] = snapshot.tenant_id
        # /provider is already in the model; ensure it is at root level
        await self._snapshots_container().upsert_item(doc)
        logger.info("Saved snapshot %s (tenant=%s)", snapshot.id, snapshot.tenant_id or "-")
        return snapshot.id

    # ------------------------------------------------------------------
    # Finding operations  (partition key: /subscription_id)
    # ------------------------------------------------------------------

    async def save_finding(self, finding: FindingResult) -> str:
        """Persist a FindingResult. Returns the finding_id."""
        doc = finding.model_dump(mode="json")
        sub_id = (
            finding.resource_snapshot.subscription_id
            if finding.resource_snapshot
            else "unknown"
        )
        doc["id"] = finding.finding_id
        # Root-level subscription_id for partition key /subscription_id
        doc["subscription_id"] = sub_id
        # Root-level tenant_id for tenant-scoped queries (Phase 1 isolation)
        doc["tenant_id"] = finding.tenant_id or (
            finding.resource_snapshot.tenant_id if finding.resource_snapshot else ""
        )
        await self._findings_container().upsert_item(doc)
        logger.info(
            "Saved finding %s (tenant=%s)", finding.finding_id, doc["tenant_id"] or "-"
        )
        return finding.finding_id

    async def get_findings(
        self,
        subscription_id: str,
        limit: int = 50,
        *,
        tenant_id: str = "",
    ) -> list[FindingResult]:
        """Return findings for a subscription, newest first.

        When `tenant_id` is provided, the query is scoped to that tenant
        (Phase 1 isolation). When empty, legacy behaviour is preserved for
        pre-backfill data.
        """
        query, params = _build_findings_query(
            tenant_id=tenant_id, subscription_id=subscription_id, limit=limit
        )
        items: list[dict[str, Any]] = []
        async for item in self._findings_container().query_items(
            query=query, parameters=params, partition_key=subscription_id
        ):
            items.append(item)
        return [FindingResult.model_validate(i) for i in items]

    async def get_finding(
        self,
        finding_id: str,
        subscription_id: str | None = None,
        *,
        tenant_id: str = "",
    ) -> FindingResult | None:
        """Retrieve a single FindingResult by finding_id.

        When `tenant_id` is provided, the result is rejected if its
        tenant_id does not match (defence-in-depth against guessed
        finding_ids).
        """
        if subscription_id:
            try:
                item = await self._findings_container().read_item(
                    item=finding_id, partition_key=subscription_id,
                )
                if tenant_id and str(item.get("tenant_id", "")) not in (
                    "",
                    tenant_id,
                ):
                    return None
                return FindingResult.model_validate(item)
            except Exception:
                return None
        # Cross-partition fallback (tenant-filtered when tenant_id given)
        query, params = _build_finding_lookup_query(
            tenant_id=tenant_id, finding_id=finding_id
        )
        async for item in self._findings_container().query_items(  # type: ignore[assignment]
            query=query, parameters=params,
            enable_cross_partition_query=True,
        ):
            return FindingResult.model_validate(item)
        return None

    # ------------------------------------------------------------------
    # Remediation card operations  (partition key: /finding_id)
    # ------------------------------------------------------------------

    async def save_remediation_card(self, card: RemediationCard) -> str:
        """Persist a RemediationCard. Returns the card_id."""
        doc = card.model_dump(mode="json")
        doc["id"] = card.card_id
        # Root-level finding_id for partition key /finding_id
        finding_id = (
            card.finding_result.finding_id if card.finding_result else "unknown"
        )
        doc["finding_id"] = finding_id
        # Root-level tenant_id for tenant-scoped queries (Phase 1 isolation)
        doc["tenant_id"] = card.tenant_id or (
            card.finding_result.tenant_id if card.finding_result else ""
        )
        await self._remediations_container().upsert_item(doc)
        logger.info(
            "Saved remediation card %s (tenant=%s)", card.card_id, doc["tenant_id"] or "-"
        )
        return card.card_id

    async def get_remediation_card(self, card_id: str) -> RemediationCard | None:
        """Retrieve a single RemediationCard by id (cross-partition query)."""
        query = "SELECT * FROM c WHERE c.card_id = @card_id"
        params: list[dict[str, object]] = [{"name": "@card_id", "value": card_id}]
        async for item in self._remediations_container().query_items(
            query=query, parameters=params, enable_cross_partition_query=True
        ):
            return RemediationCard.model_validate(item)
        return None

    # ------------------------------------------------------------------
    # Scan result operations  (system container, partition key: /type)
    # ------------------------------------------------------------------

    async def save_scan_result(self, scan_result: dict[str, Any]) -> None:
        """Persist a scan result document to the system container."""
        # Ensure /type is set for partition key
        scan_result.setdefault("type", "scan_result")
        await self._system_container().upsert_item(scan_result)
        logger.info("Saved scan result %s", scan_result.get("scan_id", "unknown"))

    async def get_scan_result(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve a scan result by scan_id."""
        query = (
            "SELECT * FROM c "
            "WHERE c.scan_id = @scan_id AND c.type = 'scan_result'"
        )
        params: list[dict[str, object]] = [{"name": "@scan_id", "value": scan_id}]
        async for item in self._system_container().query_items(
            query=query, parameters=params, partition_key="scan_result"
        ):
            return dict(item)
        return None

    # ------------------------------------------------------------------
    # Capability flags  (system container, type = "capability")
    # ------------------------------------------------------------------

    async def save_capability_flags(
        self, sub_id: str, flags: CapabilityFlags
    ) -> None:
        """Store capability flags for a subscription."""
        from dataclasses import asdict

        doc: dict[str, Any] = asdict(flags)
        doc["id"] = f"capability:{sub_id}"
        doc["type"] = "capability"
        doc["detected_at"] = doc["detected_at"].isoformat()
        await self._system_container().upsert_item(doc)
        logger.info("Saved capability flags for %s", sub_id)

    async def get_capability_flags(self, sub_id: str) -> CapabilityFlags | None:
        """Retrieve capability flags for a subscription."""
        try:
            item = await self._system_container().read_item(
                item=f"capability:{sub_id}", partition_key="capability"
            )
            return CapabilityFlags(
                tier1_available=item.get("tier1_available", True),
                tier2_available=item.get("tier2_available", False),
                tier3_available=item.get("tier3_available", False),
                detected_at=datetime.fromisoformat(item["detected_at"]).replace(
                    tzinfo=timezone.utc
                )
                if isinstance(item.get("detected_at"), str)
                else datetime.now(timezone.utc),
            )
        except Exception:
            logger.debug("No capability flags found for %s", sub_id)
            return None
