"""CloudGuardIQ -- Subscriptions repository (Cosmos-backed, in-memory fallback).

The ``subscriptions`` container stores one document per (tenant_id,
subscription_id) pair. The partition key is ``/tenant_id`` so all of a
tenant's subscriptions live in the same logical partition.

When Cosmos is not configured (local dev / tests), an in-memory store keeps
the rest of the stack working without Azure dependencies.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cloudguardiq.core.config import Settings

logger = logging.getLogger(__name__)


class SubscriptionRecord(BaseModel):
    """One linked Azure subscription owned by a CloudGuardIQ tenant."""

    tenant_id: str
    subscription_id: str
    display_name: str = ""
    state: str = "Enabled"  # "Enabled" | "Disabled"
    added_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    last_scan_at: datetime | None = None

    @property
    def doc_id(self) -> str:
        """Composite Cosmos document id ``{tenant}:{sub}``."""
        return f"{self.tenant_id}:{self.subscription_id}"

    def to_document(self) -> dict[str, Any]:
        """Serialise to a Cosmos-friendly dict."""
        return {
            "id": self.doc_id,
            "tenant_id": self.tenant_id,
            "subscription_id": self.subscription_id,
            "display_name": self.display_name,
            "state": self.state,
            "added_at": self.added_at.isoformat(),
            "last_scan_at": (
                self.last_scan_at.isoformat() if self.last_scan_at else None
            ),
        }

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> SubscriptionRecord:
        """Deserialise a Cosmos document into a :class:`SubscriptionRecord`."""

        def _parse_dt(value: Any) -> datetime | None:
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value)
                except ValueError:
                    return None
            if isinstance(value, datetime):
                return value
            return None

        added = _parse_dt(doc.get("added_at")) or datetime.now(timezone.utc)
        last_scan = _parse_dt(doc.get("last_scan_at"))
        return cls(
            tenant_id=str(doc.get("tenant_id", "")),
            subscription_id=str(doc.get("subscription_id", "")),
            display_name=str(doc.get("display_name", "")),
            state=str(doc.get("state", "Enabled")),
            added_at=added,
            last_scan_at=last_scan,
        )


class SubscriptionsRepository:
    """Read/write linked-subscription records from Cosmos (or memory)."""

    def __init__(self, settings: Settings, cosmos_db: Any | None = None) -> None:
        """Create a repository.

        *cosmos_db* is a :class:`DatabaseProxy` from ``azure.cosmos.aio``. When
        ``None``, an in-memory dict is used (tests / local dev).
        """
        self._settings = settings
        self._db = cosmos_db
        # key: (tenant_id, subscription_id)
        self._memory: dict[tuple[str, str], SubscriptionRecord] = {}

    def _container(self) -> Any | None:
        """Return the Cosmos container proxy, or ``None`` for memory mode."""
        if self._db is None:
            return None
        return self._db.get_container_client(
            self._settings.cosmos_container_subscriptions,
        )

    async def list(self, tenant_id: str) -> list[SubscriptionRecord]:
        """Return all subscriptions linked to *tenant_id*, oldest first."""
        container = self._container()
        if container is None:
            recs = [
                rec
                for (tid, _sid), rec in self._memory.items()
                if tid == tenant_id
            ]
            return sorted(recs, key=lambda r: r.added_at)

        items: list[SubscriptionRecord] = []
        try:
            async for item in container.query_items(
                query="SELECT * FROM c WHERE c.tenant_id = @tid ORDER BY c.added_at ASC",
                parameters=[{"name": "@tid", "value": tenant_id}],
                partition_key=tenant_id,
            ):
                items.append(SubscriptionRecord.from_document(item))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Subscriptions list failed: %s", exc)
        return items

    async def count(self, tenant_id: str) -> int:
        """Return the number of subscriptions linked to *tenant_id*."""
        return len(await self.list(tenant_id))

    async def get(
        self, tenant_id: str, subscription_id: str
    ) -> SubscriptionRecord | None:
        """Return a single subscription record or ``None``."""
        container = self._container()
        if container is None:
            return self._memory.get((tenant_id, subscription_id))
        try:
            doc = await container.read_item(
                item=f"{tenant_id}:{subscription_id}",
                partition_key=tenant_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "Subscription not found %s/%s: %s",
                tenant_id, subscription_id, exc,
            )
            return None
        return SubscriptionRecord.from_document(doc)

    async def upsert(
        self, record: SubscriptionRecord
    ) -> SubscriptionRecord:
        """Insert or update a subscription record."""
        container = self._container()
        if container is None:
            self._memory[(record.tenant_id, record.subscription_id)] = record
            return record
        try:
            await container.upsert_item(record.to_document())
        except Exception as exc:
            logger.warning("Subscription upsert failed: %s", exc)
            raise
        return record

    async def delete(self, tenant_id: str, subscription_id: str) -> bool:
        """Remove a subscription record. Returns ``True`` if it existed."""
        container = self._container()
        if container is None:
            existed = (tenant_id, subscription_id) in self._memory
            self._memory.pop((tenant_id, subscription_id), None)
            return existed
        try:
            await container.delete_item(
                item=f"{tenant_id}:{subscription_id}",
                partition_key=tenant_id,
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "Subscription delete miss %s/%s: %s",
                tenant_id, subscription_id, exc,
            )
            return False
