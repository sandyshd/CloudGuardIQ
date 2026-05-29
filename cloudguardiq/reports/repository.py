"""Repository for compliance report metadata.

Persists :class:`ReportRecord` rows in the Cosmos ``system`` container
under partition key ``"report"``. Falls back to an in-memory dict when
no Cosmos repository is configured (tests / local dev).
"""

from __future__ import annotations

import logging
from typing import Any

from cloudguardiq.core.database import CosmosRepository
from cloudguardiq.reports.models import ReportRecord

logger = logging.getLogger(__name__)


_TYPE = "report"


class ReportsRepository:
    """Async persistence for ReportRecord metadata."""

    def __init__(self, cosmos: CosmosRepository | None) -> None:
        self._cosmos = cosmos
        self._memory: dict[str, ReportRecord] = {}

    async def save(self, record: ReportRecord) -> ReportRecord:
        if self._cosmos is None or self._cosmos._db is None:  # noqa: SLF001
            self._memory[record.report_id] = record
            return record
        doc = record.model_dump(mode="json")
        doc["id"] = record.report_id
        doc["type"] = _TYPE
        await self._cosmos._system_container().upsert_item(doc)  # noqa: SLF001
        return record

    async def get(self, report_id: str) -> ReportRecord | None:
        if self._cosmos is None or self._cosmos._db is None:  # noqa: SLF001
            return self._memory.get(report_id)
        try:
            item = await self._cosmos._system_container().read_item(  # noqa: SLF001
                item=report_id, partition_key=_TYPE,
            )
        except Exception:
            return None
        return ReportRecord.model_validate(item)

    async def list_for_subscription(
        self,
        *,
        subscription_id: str,
        tenant_id: str = "",
        limit: int = 50,
    ) -> list[ReportRecord]:
        if self._cosmos is None or self._cosmos._db is None:  # noqa: SLF001
            rows = [
                r for r in self._memory.values()
                if r.subscription_id == subscription_id
                and (not tenant_id or r.tenant_id == tenant_id)
            ]
            rows.sort(key=lambda r: r.generated_at, reverse=True)
            return rows[:limit]
        query = (
            "SELECT TOP @limit * FROM c "
            "WHERE c.type = @type AND c.subscription_id = @sub "
            + ("AND c.tenant_id = @tenant " if tenant_id else "")
            + "ORDER BY c.generated_at DESC"
        )
        params: list[dict[str, Any]] = [
            {"name": "@limit", "value": int(limit)},
            {"name": "@type", "value": _TYPE},
            {"name": "@sub", "value": subscription_id},
        ]
        if tenant_id:
            params.append({"name": "@tenant", "value": tenant_id})
        results: list[ReportRecord] = []
        async for item in self._cosmos._system_container().query_items(  # noqa: SLF001
            query=query, parameters=params, partition_key=_TYPE,
        ):
            try:
                results.append(ReportRecord.model_validate(item))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping malformed report row: %s", exc)
        return results
