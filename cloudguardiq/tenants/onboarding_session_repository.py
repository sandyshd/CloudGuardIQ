"""CloudGuardIQ -- Onboarding session repository for streamlined flow.

Stores operator-driven customer onboarding sessions so the UI can track
status without relying on fragile browser session state.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cloudguardiq.core.config import Settings


class OnboardingSession(BaseModel):
    """Tracks a customer onboarding run started by an operator."""

    session_id: str
    operator_tenant_id: str
    customer_tenant_id: str
    status: str = "pending_consent"
    consented_at: datetime | None = None
    reader_granted_at: datetime | None = None
    discovered_subscription_ids: list[str] = Field(default_factory=list)
    connected_subscription_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def doc_id(self) -> str:
        """Cosmos document id."""
        return self.session_id

    def to_document(self) -> dict[str, Any]:
        """Serialise to Cosmos document shape."""
        return {
            "id": self.doc_id,
            "session_id": self.session_id,
            "operator_tenant_id": self.operator_tenant_id,
            "customer_tenant_id": self.customer_tenant_id,
            "status": self.status,
            "consented_at": (
                self.consented_at.isoformat() if self.consented_at else None
            ),
            "reader_granted_at": (
                self.reader_granted_at.isoformat() if self.reader_granted_at else None
            ),
            "discovered_subscription_ids": self.discovered_subscription_ids,
            "connected_subscription_ids": self.connected_subscription_ids,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> OnboardingSession:
        """Deserialise from Cosmos document."""

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
            session_id=str(doc.get("session_id", "")),
            operator_tenant_id=str(doc.get("operator_tenant_id", "")),
            customer_tenant_id=str(doc.get("customer_tenant_id", "")),
            status=str(doc.get("status", "pending_consent")),
            consented_at=_parse_dt(doc.get("consented_at")),
            reader_granted_at=_parse_dt(doc.get("reader_granted_at")),
            discovered_subscription_ids=list(doc.get("discovered_subscription_ids", [])),
            connected_subscription_ids=list(doc.get("connected_subscription_ids", [])),
            created_at=_parse_dt(doc.get("created_at")) or now,
            updated_at=_parse_dt(doc.get("updated_at")) or now,
        )


class OnboardingSessionRepository:
    """Read/write onboarding session records from Cosmos (or memory)."""

    def __init__(self, settings: Settings, cosmos_db: Any | None = None) -> None:
        self._settings = settings
        self._db = cosmos_db
        self._memory: dict[tuple[str, str], OnboardingSession] = {}

    def _container(self) -> Any | None:
        if self._db is None:
            return None
        return self._db.get_container_client(
            self._settings.cosmos_container_onboarding_sessions,
        )

    async def get(
        self,
        operator_tenant_id: str,
        session_id: str,
    ) -> OnboardingSession | None:
        """Return one session or None."""
        key = (operator_tenant_id, session_id)
        container = self._container()
        if container is None:
            return self._memory.get(key)

        try:
            doc = await container.read_item(
                item=session_id,
                partition_key=operator_tenant_id,
            )
        except Exception:
            return None
        return OnboardingSession.from_document(doc)

    async def upsert(self, session: OnboardingSession) -> OnboardingSession:
        """Insert or update a session."""
        session.updated_at = datetime.now(timezone.utc)
        key = (session.operator_tenant_id, session.session_id)
        container = self._container()
        if container is None:
            self._memory[key] = session
            return session

        await container.upsert_item(session.to_document())
        return session
