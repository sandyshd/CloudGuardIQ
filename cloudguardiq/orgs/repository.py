"""CloudGuardIQ -- organisation (org_id) identity store (Phase 2).

Maps an authenticated Microsoft Entra External ID (CIAM) subject to a
stable, provider-independent ``org_id``. CIAM users (typically AWS/GCP-only
customers) have no Azure tenant, so their data scope cannot be derived from
a ``tid``. Instead, the first time a subject signs in we mint a fresh
``org_id`` (see :func:`cloudguardiq.core.identity.mint_org_id`) and persist
the mapping; every subsequent login resolves the same ``org_id``.

Cosmos container: ``orgs`` (PK ``/subject_key``). One document per user
subject. An in-memory fallback is used for tests / local dev where Cosmos
is not configured.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cloudguardiq.core.config import Settings
from cloudguardiq.core.identity import mint_org_id

logger = logging.getLogger(__name__)


def build_subject_key(issuer: str, subject: str) -> str:
    """Return the stable lookup key for a CIAM identity.

    The ``sub`` claim is only guaranteed unique within an issuer, so the
    key combines both. Whitespace is stripped to avoid duplicate orgs.

    :param issuer: The token ``iss`` claim.
    :param subject: The token ``sub`` claim.
    :returns: A stable ``"{issuer}|{subject}"`` key.
    """
    return f"{issuer.strip()}|{subject.strip()}"


class OrgRecord(BaseModel):
    """One organisation account mapped from a CIAM subject."""

    subject_key: str
    org_id: str
    subject: str = ""
    issuer: str = ""
    email: str = ""
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    @property
    def doc_id(self) -> str:
        """Cosmos document id (one record per subject)."""
        return self.subject_key

    def to_document(self) -> dict[str, Any]:
        """Serialise to a Cosmos document."""
        return {
            "id": self.doc_id,
            "subject_key": self.subject_key,
            "org_id": self.org_id,
            "subject": self.subject,
            "issuer": self.issuer,
            "email": self.email,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> OrgRecord:
        """Deserialise from a Cosmos document."""
        created = doc.get("created_at")
        if isinstance(created, str):
            try:
                created_dt = datetime.fromisoformat(created)
            except ValueError:
                created_dt = datetime.now(timezone.utc)
        elif isinstance(created, datetime):
            created_dt = created
        else:
            created_dt = datetime.now(timezone.utc)
        return cls(
            subject_key=str(doc.get("subject_key", "")),
            org_id=str(doc.get("org_id", "")),
            subject=str(doc.get("subject", "")),
            issuer=str(doc.get("issuer", "")),
            email=str(doc.get("email", "")),
            created_at=created_dt,
        )


class OrgRepository:
    """Read/write organisation records from Cosmos (or memory)."""

    def __init__(
        self, settings: Settings, cosmos_db: Any | None = None,
    ) -> None:
        """Create a repository.

        :param settings: Application settings (for the container name).
        :param cosmos_db: A ``DatabaseProxy`` from ``azure.cosmos.aio``.
            When ``None``, an in-memory dict is used (tests / local dev).
        """
        self._settings = settings
        self._db = cosmos_db
        self._memory: dict[str, OrgRecord] = {}

    def _container(self) -> Any | None:
        if self._db is None:
            return None
        return self._db.get_container_client(
            self._settings.cosmos_container_orgs,
        )

    async def get_by_subject_key(self, subject_key: str) -> OrgRecord | None:
        """Return the org record for *subject_key* or ``None``."""
        container = self._container()
        if container is None:
            return self._memory.get(subject_key)
        try:
            doc = await container.read_item(
                item=subject_key,
                partition_key=subject_key,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("OrgRecord miss %s: %s", subject_key, exc)
            return None
        return OrgRecord.from_document(doc)

    async def upsert(self, record: OrgRecord) -> OrgRecord:
        """Insert or update an org record."""
        container = self._container()
        if container is None:
            self._memory[record.subject_key] = record
            return record
        try:
            await container.upsert_item(record.to_document())
        except Exception as exc:
            logger.warning("OrgRecord upsert failed: %s", exc)
            raise
        return record

    async def provision(
        self,
        *,
        issuer: str,
        subject: str,
        email: str = "",
    ) -> OrgRecord:
        """Resolve the org record for a CIAM identity, creating it if new.

        The first time a subject is seen a fresh ``org_id`` is minted and
        persisted; subsequent calls return the existing record so the
        ``org_id`` is stable across logins.

        :param issuer: The token ``iss`` claim.
        :param subject: The token ``sub`` claim.
        :param email: Optional email captured for display / contact.
        :returns: The resolved (existing or newly created) org record.
        """
        subject_key = build_subject_key(issuer, subject)
        existing = await self.get_by_subject_key(subject_key)
        if existing is not None:
            return existing
        record = OrgRecord(
            subject_key=subject_key,
            org_id=mint_org_id(),
            subject=subject.strip(),
            issuer=issuer.strip(),
            email=email.strip(),
        )
        saved = await self.upsert(record)
        logger.info(
            "Provisioned new org org_id=%s issuer=%s", saved.org_id, issuer,
        )
        return saved
