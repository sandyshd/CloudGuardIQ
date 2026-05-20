"""CloudGuardIQ -- Cloud connections repository (Cosmos-backed, in-memory fallback)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cloudguardiq.core.config import Settings


class CloudConnectionRecord(BaseModel):
    """One connected cloud account/project/subscription for a tenant."""

    connection_id: str
    tenant_id: str
    provider: str
    display_name: str = ""
    linked_scopes: list[str] = Field(default_factory=list)
    target_scope: dict[str, str] = Field(default_factory=dict)
    auth_mode: str = ""
    status: str = "active"
    last_verified_at: datetime | None = None
    last_scan_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def doc_id(self) -> str:
        """Return Cosmos document id for this record."""

        return self.connection_id

    def to_document(self) -> dict[str, Any]:
        """Serialize to Cosmos document shape."""

        return {
            "id": self.doc_id,
            "connection_id": self.connection_id,
            "tenant_id": self.tenant_id,
            "provider": self.provider,
            "display_name": self.display_name,
            "linked_scopes": self.linked_scopes,
            "target_scope": self.target_scope,
            "auth_mode": self.auth_mode,
            "status": self.status,
            "last_verified_at": (
                self.last_verified_at.isoformat() if self.last_verified_at else None
            ),
            "last_scan_at": self.last_scan_at.isoformat() if self.last_scan_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> CloudConnectionRecord:
        """Deserialize a Cosmos document into a CloudConnectionRecord."""

        def _parse_dt(value: Any) -> datetime | None:
            if isinstance(value, datetime):
                return value
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value)
                except ValueError:
                    return None
            return None

        now = datetime.now(timezone.utc)
        return cls(
            connection_id=str(doc.get("connection_id", doc.get("id", ""))),
            tenant_id=str(doc.get("tenant_id", "")),
            provider=str(doc.get("provider", "")),
            display_name=str(doc.get("display_name", "")),
            linked_scopes=list(doc.get("linked_scopes", [])),
            target_scope=dict(doc.get("target_scope", {})),
            auth_mode=str(doc.get("auth_mode", "")),
            status=str(doc.get("status", "active")),
            last_verified_at=_parse_dt(doc.get("last_verified_at")),
            last_scan_at=_parse_dt(doc.get("last_scan_at")),
            created_at=_parse_dt(doc.get("created_at")) or now,
            updated_at=_parse_dt(doc.get("updated_at")) or now,
        )


class CloudConnectionRepository:
    """Read/write cloud connection records from Cosmos (or memory)."""

    def __init__(self, settings: Settings, cosmos_db: Any | None = None) -> None:
        """Create repository in Cosmos mode or in-memory mode."""

        self._settings = settings
        self._db = cosmos_db
        self._memory: dict[tuple[str, str], CloudConnectionRecord] = {}

    def _container(self) -> Any | None:
        """Return Cosmos container client or None for memory mode."""

        if self._db is None:
            return None
        return self._db.get_container_client(
            self._settings.cosmos_container_cloud_connections,
        )

    async def list(self, tenant_id: str) -> list[CloudConnectionRecord]:
        """Return all cloud connections for tenant_id."""

        container = self._container()
        if container is None:
            rows = [
                rec for (tid, _cid), rec in self._memory.items() if tid == tenant_id
            ]
            return sorted(rows, key=lambda r: r.created_at)

        out: list[CloudConnectionRecord] = []
        query = (
            "SELECT * FROM c WHERE c.tenant_id = @tid ORDER BY c.created_at ASC"
        )
        params = [{"name": "@tid", "value": tenant_id}]
        async for doc in container.query_items(
            query=query,
            parameters=params,
            partition_key=tenant_id,
        ):
            out.append(CloudConnectionRecord.from_document(doc))
        return out

    async def get(
        self,
        tenant_id: str,
        connection_id: str,
    ) -> CloudConnectionRecord | None:
        """Return one cloud connection by tenant and id."""

        container = self._container()
        if container is None:
            return self._memory.get((tenant_id, connection_id))

        try:
            doc = await container.read_item(item=connection_id, partition_key=tenant_id)
        except Exception:
            return None
        return CloudConnectionRecord.from_document(doc)

    async def upsert(self, record: CloudConnectionRecord) -> CloudConnectionRecord:
        """Insert or update one cloud connection record."""

        record.updated_at = datetime.now(timezone.utc)
        container = self._container()
        if container is None:
            self._memory[(record.tenant_id, record.connection_id)] = record
            return record

        await container.upsert_item(record.to_document())
        return record
