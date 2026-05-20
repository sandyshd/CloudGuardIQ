"""CloudGuardIQ -- Credential reference repository (Cosmos-backed, in-memory fallback)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cloudguardiq.core.config import Settings


class CredentialRefRecord(BaseModel):
    """References provider credential metadata for a cloud connection."""

    credential_ref_id: str
    tenant_id: str
    connection_id: str
    provider: str
    secret_ref: str = ""
    token_metadata: dict[str, str] = Field(default_factory=dict)
    rotation_policy: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def doc_id(self) -> str:
        """Return Cosmos document id."""

        return self.credential_ref_id

    def to_document(self) -> dict[str, Any]:
        """Serialize to Cosmos document shape."""

        return {
            "id": self.doc_id,
            "credential_ref_id": self.credential_ref_id,
            "tenant_id": self.tenant_id,
            "connection_id": self.connection_id,
            "provider": self.provider,
            "secret_ref": self.secret_ref,
            "token_metadata": self.token_metadata,
            "rotation_policy": self.rotation_policy,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> CredentialRefRecord:
        """Deserialize from Cosmos document."""

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
            credential_ref_id=str(doc.get("credential_ref_id", doc.get("id", ""))),
            tenant_id=str(doc.get("tenant_id", "")),
            connection_id=str(doc.get("connection_id", "")),
            provider=str(doc.get("provider", "")),
            secret_ref=str(doc.get("secret_ref", "")),
            token_metadata=dict(doc.get("token_metadata", {})),
            rotation_policy=str(doc.get("rotation_policy", "")),
            created_at=_parse_dt(doc.get("created_at")) or now,
            updated_at=_parse_dt(doc.get("updated_at")) or now,
        )


class CredentialRefRepository:
    """Read/write credential reference records."""

    def __init__(self, settings: Settings, cosmos_db: Any | None = None) -> None:
        """Create repository in Cosmos or memory mode."""

        self._settings = settings
        self._db = cosmos_db
        self._memory: dict[tuple[str, str], CredentialRefRecord] = {}

    def _container(self) -> Any | None:
        """Return Cosmos container client or None for memory mode."""

        if self._db is None:
            return None
        return self._db.get_container_client(
            self._settings.cosmos_container_credential_refs,
        )

    async def upsert(self, record: CredentialRefRecord) -> CredentialRefRecord:
        """Insert or update credential reference record."""

        record.updated_at = datetime.now(timezone.utc)
        container = self._container()
        key = (record.tenant_id, record.connection_id)
        if container is None:
            self._memory[key] = record
            return record

        await container.upsert_item(record.to_document())
        return record

    async def get_by_connection(
        self,
        tenant_id: str,
        connection_id: str,
    ) -> CredentialRefRecord | None:
        """Return one credential ref for a connection, if present."""

        container = self._container()
        if container is None:
            return self._memory.get((tenant_id, connection_id))

        query = (
            "SELECT TOP 1 * FROM c "
            "WHERE c.tenant_id = @tid AND c.connection_id = @cid"
        )
        params = [
            {"name": "@tid", "value": tenant_id},
            {"name": "@cid", "value": connection_id},
        ]
        async for doc in container.query_items(
            query=query,
            parameters=params,
            partition_key=tenant_id,
        ):
            return CredentialRefRecord.from_document(doc)
        return None

    async def delete_by_connection(self, tenant_id: str, connection_id: str) -> None:
        """Delete credential ref associated with a cloud connection."""

        container = self._container()
        key = (tenant_id, connection_id)
        if container is None:
            self._memory.pop(key, None)
            return

        rec = await self.get_by_connection(tenant_id, connection_id)
        if rec is None:
            return
        await container.delete_item(item=rec.doc_id, partition_key=tenant_id)
