"""CloudGuardIQ -- Cosmos DB repository (async)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from azure.cosmos.aio import ContainerProxy, CosmosClient, DatabaseProxy

from cloudguardiq.adapters.base import CapabilityFlags
from cloudguardiq.core.config import Settings
from cloudguardiq.core.models import FindingResult, RemediationCard, ResourceSnapshot

logger = logging.getLogger(__name__)


class CosmosRepository:
    """Async Cosmos DB repository for CloudGuardIQ entities."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: CosmosClient | None = None
        self._db: DatabaseProxy | None = None

    async def connect(self) -> None:
        """Initialise the Cosmos client and database proxy."""
        self._client = CosmosClient(
            url=self._settings.cosmos_endpoint,
            credential=self._settings.cosmos_key,
        )
        self._db = self._client.get_database_client(self._settings.cosmos_database)
        logger.info("Connected to Cosmos DB: %s", self._settings.cosmos_database)

    async def close(self) -> None:
        """Close the Cosmos client."""
        if self._client:
            await self._client.close()
            logger.info("Cosmos DB connection closed")

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
    # Snapshot operations
    # ------------------------------------------------------------------

    async def save_snapshot(self, snapshot: ResourceSnapshot) -> str:
        """Persist a ResourceSnapshot. Returns the snapshot id."""
        doc = snapshot.model_dump(mode="json")
        doc["partition_key"] = snapshot.subscription_id
        await self._snapshots_container().upsert_item(doc)
        logger.info("Saved snapshot %s", snapshot.id)
        return snapshot.id

    # ------------------------------------------------------------------
    # Finding operations
    # ------------------------------------------------------------------

    async def save_finding(self, finding: FindingResult) -> str:
        """Persist a FindingResult. Returns the finding_id."""
        doc = finding.model_dump(mode="json")
        sub_id = (
            finding.resource_snapshot.subscription_id
            if finding.resource_snapshot
            else "unknown"
        )
        doc["partition_key"] = sub_id
        await self._findings_container().upsert_item(doc)
        logger.info("Saved finding %s", finding.finding_id)
        return finding.finding_id

    async def get_findings(
        self, subscription_id: str, limit: int = 50
    ) -> list[FindingResult]:
        """Return findings for a subscription, newest first."""
        query = (
            "SELECT TOP @limit * FROM c "
            "WHERE c.partition_key = @sub_id "
            "ORDER BY c.detected_at DESC"
        )
        params: list[dict[str, Any]] = [
            {"name": "@limit", "value": limit},
            {"name": "@sub_id", "value": subscription_id},
        ]
        items: list[dict[str, Any]] = []
        async for item in self._findings_container().query_items(
            query=query, parameters=params, partition_key=subscription_id
        ):
            items.append(item)
        return [FindingResult.model_validate(i) for i in items]

    # ------------------------------------------------------------------
    # Remediation card operations
    # ------------------------------------------------------------------

    async def save_remediation_card(self, card: RemediationCard) -> str:
        """Persist a RemediationCard. Returns the card_id."""
        doc = card.model_dump(mode="json")
        sub_id = "unknown"
        if card.finding_result and card.finding_result.resource_snapshot:
            sub_id = card.finding_result.resource_snapshot.subscription_id
        doc["partition_key"] = sub_id
        await self._remediations_container().upsert_item(doc)
        logger.info("Saved remediation card %s", card.card_id)
        return card.card_id

    async def get_remediation_card(self, card_id: str) -> RemediationCard | None:
        """Retrieve a single RemediationCard by id (cross-partition query)."""
        query = "SELECT * FROM c WHERE c.card_id = @card_id"
        params: list[dict[str, Any]] = [{"name": "@card_id", "value": card_id}]
        async for item in self._remediations_container().query_items(
            query=query, parameters=params, enable_cross_partition_query=True
        ):
            return RemediationCard.model_validate(item)
        return None

    # ------------------------------------------------------------------
    # Capability flags (system container, partition_key = "system")
    # ------------------------------------------------------------------

    async def save_capability_flags(
        self, sub_id: str, flags: CapabilityFlags
    ) -> None:
        """Store capability flags for a subscription."""
        from dataclasses import asdict

        doc: dict[str, Any] = asdict(flags)
        doc["id"] = f"capability:{sub_id}"
        doc["partition_key"] = "system"
        doc["detected_at"] = doc["detected_at"].isoformat()
        await self._system_container().upsert_item(doc)
        logger.info("Saved capability flags for %s", sub_id)

    async def get_capability_flags(self, sub_id: str) -> CapabilityFlags | None:
        """Retrieve capability flags for a subscription."""
        try:
            item = await self._system_container().read_item(
                item=f"capability:{sub_id}", partition_key="system"
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
