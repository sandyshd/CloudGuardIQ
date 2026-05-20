"""CloudGuardIQ -- Tenant consent repository (Phase 3.3).

Records the fact that a customer-tenant administrator has granted admin
consent for the CloudGuardIQ multi-tenant app to read their Azure
resources. One document per ``customer_tenant_id`` (Azure tenant that
owns the subscriptions being onboarded). Used by ``POST /subscriptions``
to refuse cross-tenant adds when consent is not on record.

Cosmos container: ``tenant_consents`` (PK ``/customer_tenant_id``).
In-memory fallback is used for tests / local dev where Cosmos is not
configured.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cloudguardiq.core.config import Settings

logger = logging.getLogger(__name__)


class TenantConsent(BaseModel):
    """One record proving admin consent was granted for a tenant."""

    customer_tenant_id: str
    consented_by: str = ""  # oid of the admin who clicked consent
    consented_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    revoked_at: datetime | None = None

    @property
    def doc_id(self) -> str:
        """Cosmos document id (one consent record per tenant)."""
        return self.customer_tenant_id

    @property
    def is_active(self) -> bool:
        """Return ``True`` when consent has not been revoked."""
        return self.revoked_at is None

    def to_document(self) -> dict[str, Any]:
        """Serialise to a Cosmos document."""
        return {
            "id": self.doc_id,
            "customer_tenant_id": self.customer_tenant_id,
            "consented_by": self.consented_by,
            "consented_at": self.consented_at.isoformat(),
            "revoked_at": (
                self.revoked_at.isoformat() if self.revoked_at else None
            ),
        }

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> TenantConsent:
        """Deserialise from a Cosmos document."""

        def _parse_dt(value: Any) -> datetime | None:
            if isinstance(value, datetime):
                return value
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value)
                except ValueError:
                    return None
            return None

        consented = _parse_dt(doc.get("consented_at")) or datetime.now(
            timezone.utc,
        )
        revoked = _parse_dt(doc.get("revoked_at"))
        return cls(
            customer_tenant_id=str(doc.get("customer_tenant_id", "")),
            consented_by=str(doc.get("consented_by", "")),
            consented_at=consented,
            revoked_at=revoked,
        )


class TenantConsentRepository:
    """Read/write tenant-consent records from Cosmos (or memory)."""

    def __init__(
        self, settings: Settings, cosmos_db: Any | None = None,
    ) -> None:
        """Create a repository.

        *cosmos_db* is a :class:`DatabaseProxy` from ``azure.cosmos.aio``.
        When ``None``, an in-memory dict is used (tests / local dev).
        """
        self._settings = settings
        self._db = cosmos_db
        self._memory: dict[str, TenantConsent] = {}

    def _container(self) -> Any | None:
        if self._db is None:
            return None
        return self._db.get_container_client(
            self._settings.cosmos_container_tenant_consents,
        )

    async def get(self, customer_tenant_id: str) -> TenantConsent | None:
        """Return the consent record for *customer_tenant_id* or ``None``."""
        container = self._container()
        if container is None:
            return self._memory.get(customer_tenant_id)
        try:
            doc = await container.read_item(
                item=customer_tenant_id,
                partition_key=customer_tenant_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "TenantConsent miss %s: %s", customer_tenant_id, exc,
            )
            return None
        return TenantConsent.from_document(doc)

    async def has_active_consent(self, customer_tenant_id: str) -> bool:
        """Return ``True`` when *customer_tenant_id* has active consent."""
        rec = await self.get(customer_tenant_id)
        return rec is not None and rec.is_active

    async def upsert(self, consent: TenantConsent) -> TenantConsent:
        """Insert or update a consent record."""
        container = self._container()
        if container is None:
            self._memory[consent.customer_tenant_id] = consent
            return consent
        try:
            await container.upsert_item(consent.to_document())
        except Exception as exc:
            logger.warning("TenantConsent upsert failed: %s", exc)
            raise
        return consent

    async def revoke(self, customer_tenant_id: str) -> bool:
        """Mark consent revoked. Returns ``True`` when a record changed."""
        rec = await self.get(customer_tenant_id)
        if rec is None or rec.revoked_at is not None:
            return False
        rec.revoked_at = datetime.now(timezone.utc)
        await self.upsert(rec)
        return True
