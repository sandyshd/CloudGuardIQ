"""CloudGuardIQ -- Audit event repository (Cosmos-backed, in-memory fallback)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cloudguardiq.core.config import Settings


class AuditEventRecord(BaseModel):
    """One tenant-scoped audit event emitted by onboarding operations."""

    event_id: str
    tenant_id: str
    actor_id: str
    action: str
    provider: str
    resource_id: str
    result: str
    request_id: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: dict[str, Any] = Field(default_factory=dict)

    @property
    def doc_id(self) -> str:
        """Return Cosmos document id."""

        return self.event_id

    def to_document(self) -> dict[str, Any]:
        """Serialize to Cosmos document shape."""

        return {
            "id": self.doc_id,
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "actor_id": self.actor_id,
            "action": self.action,
            "provider": self.provider,
            "resource_id": self.resource_id,
            "result": self.result,
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> AuditEventRecord:
        """Deserialize from Cosmos document."""

        ts = doc.get("timestamp")
        if isinstance(ts, str):
            try:
                parsed = datetime.fromisoformat(ts)
            except ValueError:
                parsed = datetime.now(timezone.utc)
        elif isinstance(ts, datetime):
            parsed = ts
        else:
            parsed = datetime.now(timezone.utc)

        return cls(
            event_id=str(doc.get("event_id", doc.get("id", ""))),
            tenant_id=str(doc.get("tenant_id", "")),
            actor_id=str(doc.get("actor_id", "")),
            action=str(doc.get("action", "")),
            provider=str(doc.get("provider", "")),
            resource_id=str(doc.get("resource_id", "")),
            result=str(doc.get("result", "")),
            request_id=str(doc.get("request_id", "")),
            timestamp=parsed,
            details=dict(doc.get("details", {})),
        )


class AuditEventRepository:
    """Read/write tenant-scoped audit events."""

    def __init__(self, settings: Settings, cosmos_db: Any | None = None) -> None:
        """Create repository in Cosmos or memory mode."""

        self._settings = settings
        self._db = cosmos_db
        self._memory: dict[tuple[str, str], AuditEventRecord] = {}

    def _container(self) -> Any | None:
        """Return Cosmos container client or None for memory mode."""

        if self._db is None:
            return None
        return self._db.get_container_client(
            self._settings.cosmos_container_audit_events,
        )

    async def append(self, record: AuditEventRecord) -> AuditEventRecord:
        """Append an audit event record."""

        container = self._container()
        key = (record.tenant_id, record.event_id)
        if container is None:
            self._memory[key] = record
            return record

        await container.upsert_item(record.to_document())
        return record

    async def list_recent(self, tenant_id: str, limit: int = 50) -> list[AuditEventRecord]:
        """Return recent audit events for tenant_id (descending by timestamp)."""

        container = self._container()
        if container is None:
            rows = [
                rec for (tid, _eid), rec in self._memory.items() if tid == tenant_id
            ]
            rows.sort(key=lambda r: r.timestamp, reverse=True)
            return rows[:limit]

        out: list[AuditEventRecord] = []
        query = (
            "SELECT TOP @limit * FROM c WHERE c.tenant_id = @tid "
            "ORDER BY c.timestamp DESC"
        )
        params = [
            {"name": "@limit", "value": limit},
            {"name": "@tid", "value": tenant_id},
        ]
        async for doc in container.query_items(
            query=query,
            parameters=params,
            partition_key=tenant_id,
        ):
            out.append(AuditEventRecord.from_document(doc))
        return out
