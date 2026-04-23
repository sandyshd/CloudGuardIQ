"""CloudGuardIQ -- Billing repository (Cosmos-backed, with in-memory fallback).

The billing container stores one document per tenant, keyed by tenant id.
When Cosmos is not configured (local/dev or tests), an in-memory store is used
so the rest of the stack works end-to-end without Azure dependencies.

Partition key: ``/tenant_id``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import SubscriptionTier

logger = logging.getLogger(__name__)


class BillingCustomer(BaseModel):
    """Billing record for a tenant."""

    tenant_id: str
    stripe_customer_id: str = ""
    stripe_subscription_id: str = ""
    tier: SubscriptionTier = SubscriptionTier.FREE
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    def to_document(self) -> dict[str, Any]:
        """Serialise to a Cosmos-friendly dict."""
        return {
            "id": self.tenant_id,
            "tenant_id": self.tenant_id,
            "stripe_customer_id": self.stripe_customer_id,
            "stripe_subscription_id": self.stripe_subscription_id,
            "tier": self.tier.value,
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> BillingCustomer:
        """Deserialise a Cosmos document into a :class:`BillingCustomer`."""
        raw_dt = doc.get("updated_at")
        if isinstance(raw_dt, str):
            try:
                updated = datetime.fromisoformat(raw_dt)
            except ValueError:
                updated = datetime.now(timezone.utc)
        elif isinstance(raw_dt, datetime):
            updated = raw_dt
        else:
            updated = datetime.now(timezone.utc)
        return cls(
            tenant_id=str(doc.get("tenant_id") or doc.get("id", "")),
            stripe_customer_id=str(doc.get("stripe_customer_id", "")),
            stripe_subscription_id=str(doc.get("stripe_subscription_id", "")),
            tier=SubscriptionTier(str(doc.get("tier", SubscriptionTier.FREE.value))),
            updated_at=updated,
        )


class BillingRepository:
    """Read/write billing records from Cosmos (or memory)."""

    def __init__(self, settings: Settings, cosmos_db: Any | None = None) -> None:
        """Create a repository.

        *cosmos_db* is a :class:`DatabaseProxy` from ``azure.cosmos.aio``. When
        ``None``, an in-memory dict is used.
        """
        self._settings = settings
        self._db = cosmos_db
        self._memory: dict[str, BillingCustomer] = {}

    def _container(self) -> Any | None:
        """Return the Cosmos container proxy, or None for in-memory mode."""
        if self._db is None:
            return None
        return self._db.get_container_client(
            self._settings.cosmos_container_billing,
        )

    async def get(self, tenant_id: str) -> BillingCustomer | None:
        """Return the billing record for *tenant_id*, if any."""
        container = self._container()
        if container is None:
            return self._memory.get(tenant_id)
        try:
            doc = await container.read_item(
                item=tenant_id,
                partition_key=tenant_id,
            )
        except Exception as exc:  # noqa: BLE001 - Cosmos raises many types
            logger.debug("Billing record not found for %s: %s", tenant_id, exc)
            return None
        return BillingCustomer.from_document(doc)

    async def get_by_customer_id(
        self, stripe_customer_id: str,
    ) -> BillingCustomer | None:
        """Return the record associated with *stripe_customer_id*."""
        container = self._container()
        if container is None:
            for rec in self._memory.values():
                if rec.stripe_customer_id == stripe_customer_id:
                    return rec
            return None
        query = (
            "SELECT * FROM c WHERE c.stripe_customer_id = @cid"
        )
        params = [{"name": "@cid", "value": stripe_customer_id}]
        try:
            async for item in container.query_items(
                query=query,
                parameters=params,
            ):
                return BillingCustomer.from_document(item)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Billing query failed: %s", exc)
        return None

    async def upsert(self, record: BillingCustomer) -> BillingCustomer:
        """Insert or update a billing record and return the stored copy."""
        record.updated_at = datetime.now(timezone.utc)
        container = self._container()
        if container is None:
            self._memory[record.tenant_id] = record
            return record
        try:
            await container.upsert_item(record.to_document())
        except Exception as exc:
            logger.warning("Billing upsert failed: %s", exc)
            raise
        return record
