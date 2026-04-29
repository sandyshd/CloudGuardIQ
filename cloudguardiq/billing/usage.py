"""CloudGuardIQ -- Per-tenant monthly usage counters.

Tracks resource counts that drive plan-tier enforcement (today: AI
remediation generations per calendar month). Documents are keyed by
``{tenant_id}:{YYYY-MM}`` and partitioned by tenant id for cheap reads.

When Cosmos is not configured (local/dev or tests), an in-memory dict is
used — same pattern as :class:`BillingRepository`.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cloudguardiq.core.config import Settings

logger = logging.getLogger(__name__)


def _current_period() -> str:
    """Return the current usage period in ``YYYY-MM`` form (UTC)."""
    now = datetime.now(timezone.utc)
    return f"{now.year:04d}-{now.month:02d}"


class UsageRecord(BaseModel):
    """A single tenant/period counter document."""

    tenant_id: str
    period: str = Field(default_factory=_current_period)
    ai_remediations: int = 0
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    @property
    def doc_id(self) -> str:
        """Return the composite Cosmos document id."""
        return f"{self.tenant_id}:{self.period}"

    def to_document(self) -> dict[str, Any]:
        """Serialise to a Cosmos-friendly dict."""
        return {
            "id": self.doc_id,
            "tenant_id": self.tenant_id,
            "period": self.period,
            "ai_remediations": self.ai_remediations,
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> UsageRecord:
        """Deserialise a Cosmos document."""
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
            tenant_id=str(doc.get("tenant_id", "")),
            period=str(doc.get("period", _current_period())),
            ai_remediations=int(doc.get("ai_remediations", 0)),
            updated_at=updated,
        )


class UsageRepository:
    """Read/increment usage counters from Cosmos (or memory)."""

    # Container name reused from the billing container — usage docs live
    # alongside billing customers and share the same partition key.
    def __init__(self, settings: Settings, cosmos_db: Any | None = None) -> None:
        """Create a repository.

        *cosmos_db* is an ``azure.cosmos.aio.DatabaseProxy``. When ``None``,
        an in-memory dict is used.
        """
        self._settings = settings
        self._db = cosmos_db
        self._memory: dict[str, UsageRecord] = {}

    def _container(self) -> Any | None:
        if self._db is None:
            return None
        return self._db.get_container_client(
            self._settings.cosmos_container_billing,
        )

    async def get_current(self, tenant_id: str) -> UsageRecord:
        """Return the current-period counter for *tenant_id* (zero if absent)."""
        period = _current_period()
        doc_id = f"{tenant_id}:{period}"
        container = self._container()
        if container is None:
            return self._memory.get(
                doc_id, UsageRecord(tenant_id=tenant_id, period=period),
            )
        try:
            doc = await container.read_item(
                item=doc_id, partition_key=tenant_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Usage record not found for %s: %s", doc_id, exc)
            return UsageRecord(tenant_id=tenant_id, period=period)
        return UsageRecord.from_document(doc)

    async def increment_ai_remediations(
        self, tenant_id: str, *, by: int = 1,
    ) -> UsageRecord:
        """Atomically bump the AI remediation counter for *tenant_id*.

        For the in-memory backend the increment is read-modify-write; for
        Cosmos it is a best-effort upsert (concurrency conflicts are
        acceptable since quotas are advisory and the cap has built-in
        slack at the plan level).
        """
        record = await self.get_current(tenant_id)
        record.ai_remediations += by
        record.updated_at = datetime.now(timezone.utc)
        container = self._container()
        if container is None:
            self._memory[record.doc_id] = record
            return record
        try:
            await container.upsert_item(record.to_document())
        except Exception as exc:  # noqa: BLE001
            logger.warning("Usage upsert failed for %s: %s", record.doc_id, exc)
        return record
