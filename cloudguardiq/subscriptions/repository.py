"""CloudGuardIQ -- Subscriptions repository (Cosmos-backed, in-memory fallback).

The ``subscriptions`` container stores one document per (tenant_id,
subscription_id) pair. The partition key is ``/tenant_id`` so all of a
tenant's subscriptions live in the same logical partition.

When Cosmos is not configured (local dev / tests), an in-memory store keeps
the rest of the stack working without Azure dependencies.
"""

from __future__ import annotations

import builtins
import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import CloudProvider

logger = logging.getLogger(__name__)


class SubscriptionRecord(BaseModel):
    """One linked Azure subscription owned by a CloudGuardIQ tenant."""

    tenant_id: str
    subscription_id: str
    # Multi-cloud provider this record represents. Defaults to AZURE so
    # documents written before the AWS rollout keep working. For AWS
    # connections ``subscription_id`` is reused as the canonical
    # cross-cloud connection id (==``aws_account_id``).
    provider: CloudProvider = CloudProvider.AZURE
    # AWS-specific fields. Empty for non-AWS rows.
    aws_account_id: str = ""
    aws_region: str = ""
    # AWS cross-account assume-role wiring (Phase 1 storage layer). The
    # control plane assumes ``aws_role_arn`` using ``aws_external_id`` as the
    # STS ExternalId. Empty until the onboarding flow persists them; no
    # runtime consumer yet (behaviour-neutral).
    aws_role_arn: str = ""
    aws_external_id: str = ""
    # GCP-specific field. Empty for non-GCP rows.
    gcp_project_id: str = ""
    # The Azure tenant that owns this subscription. For self-service in
    # the operator's own tenant this matches ``tenant_id``; for true
    # cross-tenant SaaS onboarding (Phase 3) ``customer_tenant_id`` is
    # the *customer's* Entra tenant whose admin granted consent.
    customer_tenant_id: str = ""
    display_name: str = ""
    state: str = "Enabled"  # "Enabled" | "Disabled" | "Removed"
    added_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    last_scan_at: datetime | None = None
    # When a user clicks Remove the record is soft-deleted (state set to
    # ``Removed``) and ``removed_at`` is stamped. The daily purge timer
    # uses this column to hard-delete records older than the retention
    # window. Re-linking the same GUID before expiry restores the row.
    removed_at: datetime | None = None

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
            "customer_tenant_id": self.customer_tenant_id or self.tenant_id,
            "provider": self.provider.value,
            "aws_account_id": self.aws_account_id,
            "aws_region": self.aws_region,
            "aws_role_arn": self.aws_role_arn,
            "aws_external_id": self.aws_external_id,
            "gcp_project_id": self.gcp_project_id,
            "display_name": self.display_name,
            "state": self.state,
            "added_at": self.added_at.isoformat(),
            "last_scan_at": (
                self.last_scan_at.isoformat() if self.last_scan_at else None
            ),
            "removed_at": (
                self.removed_at.isoformat() if self.removed_at else None
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
        removed = _parse_dt(doc.get("removed_at"))
        provider_raw = str(doc.get("provider", "") or "AZURE").upper()
        try:
            provider_enum = CloudProvider(provider_raw)
        except ValueError:
            provider_enum = CloudProvider.AZURE
        return cls(
            tenant_id=str(doc.get("tenant_id", "")),
            subscription_id=str(doc.get("subscription_id", "")),
            customer_tenant_id=str(doc.get("customer_tenant_id", "") or ""),
            provider=provider_enum,
            aws_account_id=str(doc.get("aws_account_id", "") or ""),
            aws_region=str(doc.get("aws_region", "") or ""),
            aws_role_arn=str(doc.get("aws_role_arn", "") or ""),
            aws_external_id=str(doc.get("aws_external_id", "") or ""),
            gcp_project_id=str(doc.get("gcp_project_id", "") or ""),
            display_name=str(doc.get("display_name", "")),
            state=str(doc.get("state", "Enabled")),
            added_at=added,
            last_scan_at=last_scan,
            removed_at=removed,
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

    async def list(
        self, tenant_id: str, *, include_removed: bool = False,
    ) -> list[SubscriptionRecord]:
        """Return all active subscriptions linked to *tenant_id*.

        Soft-deleted (``state == 'Removed'``) records are filtered out
        unless *include_removed* is ``True`` (used by the purge timer).
        """
        container = self._container()
        if container is None:
            recs = [
                rec
                for (tid, _sid), rec in self._memory.items()
                if tid == tenant_id
                and (include_removed or rec.state != "Removed")
            ]
            return sorted(recs, key=lambda r: r.added_at)

        items: list[SubscriptionRecord] = []
        try:
            if include_removed:
                query = (
                    "SELECT * FROM c WHERE c.tenant_id = @tid "
                    "ORDER BY c.added_at ASC"
                )
            else:
                query = (
                    "SELECT * FROM c WHERE c.tenant_id = @tid "
                    "AND (NOT IS_DEFINED(c.state) OR c.state != 'Removed') "
                    "ORDER BY c.added_at ASC"
                )
            async for item in container.query_items(
                query=query,
                parameters=[{"name": "@tid", "value": tenant_id}],
                partition_key=tenant_id,
            ):
                items.append(SubscriptionRecord.from_document(item))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Subscriptions list failed: %s", exc)
        return items

    async def list_by_customer_tenant(
        self, customer_tenant_id: str, *, include_removed: bool = False,
    ) -> builtins.list[SubscriptionRecord]:
        """Return subscriptions visible to *customer_tenant_id*.

        Used as a backwards-compatible bridge for legacy rows created when an
        operator linked customer subscriptions under the operator tenant_id.
        """
        container = self._container()
        customer_tid = customer_tenant_id.strip().lower()
        if container is None:
            recs = [
                rec
                for rec in self._memory.values()
                if (rec.customer_tenant_id or rec.tenant_id).strip().lower()
                == customer_tid
                and rec.tenant_id.strip().lower() != customer_tid
                and (include_removed or rec.state != "Removed")
            ]
            return sorted(recs, key=lambda r: r.added_at)

        items: list[SubscriptionRecord] = []
        try:
            if include_removed:
                query = (
                    "SELECT * FROM c WHERE "
                    "LOWER(c.customer_tenant_id) = @customer_tid "
                    "AND LOWER(c.tenant_id) != @customer_tid "
                    "ORDER BY c.added_at ASC"
                )
            else:
                query = (
                    "SELECT * FROM c WHERE "
                    "LOWER(c.customer_tenant_id) = @customer_tid "
                    "AND LOWER(c.tenant_id) != @customer_tid "
                    "AND (NOT IS_DEFINED(c.state) OR c.state != 'Removed') "
                    "ORDER BY c.added_at ASC"
                )
            async for item in container.query_items(
                query=query,
                parameters=[{"name": "@customer_tid", "value": customer_tid}],
            ):
                items.append(SubscriptionRecord.from_document(item))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Subscriptions list_by_customer_tenant failed: %s", exc)
        return items
    async def count(self, tenant_id: str) -> int:
        """Return the number of *active* subscriptions for *tenant_id*.

        Soft-deleted (Removed) records do not count against the tier cap.
        """
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


    async def mark_scanned(
        self, tenant_id: str, subscription_id: str,
    ) -> SubscriptionRecord | None:
        """Stamp ``last_scan_at`` for *(tenant_id, subscription_id)*.

        Returns the updated record, or ``None`` if the subscription is no
        longer registered. Called from the timer-driven scan trigger to
        enforce per-tier scan frequency caps.
        """
        rec = await self.get(tenant_id, subscription_id)
        if rec is None:
            return None
        rec.last_scan_at = datetime.now(timezone.utc)
        return await self.upsert(rec)

    async def delete(self, tenant_id: str, subscription_id: str) -> bool:
        """Soft-delete a subscription record.

        Sets ``state='Removed'`` and stamps ``removed_at`` so the daily
        purge timer can later hard-delete it (along with any orphaned
        findings/snapshots/remediations) once the retention window has
        elapsed. Re-linking the same GUID before expiry restores the row
        and reattaches its historical findings.
        """
        rec = await self.get(tenant_id, subscription_id)
        if rec is None or rec.state == "Removed":
            return False
        rec.state = "Removed"
        rec.removed_at = datetime.now(timezone.utc)
        await self.upsert(rec)
        return True

    async def hard_delete(
        self, tenant_id: str, subscription_id: str,
    ) -> bool:
        """Permanently delete a subscription record (purge timer only).

        Bypasses the soft-delete state machine; callers are responsible
        for removing dependent findings/snapshots/remediations first.
        """
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
                "Subscription hard_delete miss %s/%s: %s",
                tenant_id, subscription_id, exc,
            )
            return False

    async def list_expired_removed(
        self, retention_days: int,
    ) -> builtins.list[SubscriptionRecord]:
        """Return tombstoned records older than *retention_days*.

        Used by the purge timer to find subscriptions whose findings can
        now be hard-deleted. Cross-partition: scans every tenant.
        """
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        container = self._container()
        if container is None:
            return [
                rec
                for rec in self._memory.values()
                if rec.state == "Removed"
                and rec.removed_at is not None
                and rec.removed_at < cutoff
            ]
        items: list[SubscriptionRecord] = []
        try:
            async for item in container.query_items(
                query=(
                    "SELECT * FROM c WHERE c.state = 'Removed' "
                    "AND IS_DEFINED(c.removed_at) "
                    "AND c.removed_at < @cutoff"
                ),
                parameters=[
                    {"name": "@cutoff", "value": cutoff.isoformat()},
                ],
            ):
                items.append(SubscriptionRecord.from_document(item))
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_expired_removed failed: %s", exc)
        return items
