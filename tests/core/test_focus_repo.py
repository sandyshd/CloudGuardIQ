"""Tests for FOCUS cost record persistence (query builder + idempotent upsert)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

from cloudguardiq.core.config import Settings
from cloudguardiq.core.database import CosmosRepository, _build_focus_query
from cloudguardiq.core.enums import CloudProvider
from cloudguardiq.core.models import FocusCostRecord


class _FakeContainer:
    """Minimal async Cosmos container stub recording upserts and queries."""

    def __init__(self, items: list[dict[str, Any]] | None = None) -> None:
        self._items = items or []
        self.upserts: list[dict[str, Any]] = []
        self.store: dict[str, dict[str, Any]] = {}
        self.query_calls: list[dict[str, Any]] = []

    async def upsert_item(self, doc: dict[str, Any]) -> dict[str, Any]:
        self.upserts.append(doc)
        self.store[doc["id"]] = doc  # last-write-wins keyed by id
        return doc

    def query_items(
        self,
        *,
        query: str,
        parameters: list[dict[str, Any]] | None = None,
        partition_key: Any = None,
    ) -> Any:
        self.query_calls.append(
            {"query": query, "parameters": parameters, "partition_key": partition_key}
        )
        items = self._items

        async def _gen() -> Any:
            for item in items:
                yield item

        return _gen()


def _record(**overrides: object) -> FocusCostRecord:
    base: dict[str, object] = {
        "tenant_id": "tenant-a",
        "billing_period": "2026-05",
        "charge_period_start": datetime(2026, 5, 1, tzinfo=timezone.utc),
        "charge_period_end": datetime(2026, 5, 31, tzinfo=timezone.utc),
        "provider": CloudProvider.AZURE,
        "sub_account_id": "sub-1",
        "resource_id": "/subscriptions/sub-1/rg/vm-1",
        "sku_id": "Standard_D2s_v5",
        "billed_cost": 12.5,
    }
    base.update(overrides)
    return FocusCostRecord(**base)  # type: ignore[arg-type]


# -- query builder ----------------------------------------------------------


def test_build_focus_query_filters_by_tenant_and_sub() -> None:
    query, params = _build_focus_query(
        tenant_id="tenant-a", subscription_id="sub-1", limit=50
    )
    assert "c.tenant_id = @tenant_id" in query
    assert "c.sub_account_id = @sub_id" in query
    names = {p["name"] for p in params}
    assert {"@tenant_id", "@sub_id", "@limit"} <= names


def test_build_focus_query_without_tenant_drops_filter() -> None:
    query, _ = _build_focus_query(tenant_id="", subscription_id="sub-1")
    assert "c.tenant_id" not in query
    assert "c.sub_account_id = @sub_id" in query


def test_build_focus_query_period_bounds() -> None:
    query, params = _build_focus_query(
        tenant_id="t", subscription_id="s", from_period="2026-01", to_period="2026-06"
    )
    assert "c.billing_period >= @from_period" in query
    assert "c.billing_period <= @to_period" in query
    names = {p["name"] for p in params}
    assert {"@from_period", "@to_period"} <= names


# -- upsert -----------------------------------------------------------------


async def test_upsert_focus_records_writes_each_with_dedup_id() -> None:
    repo = CosmosRepository(Settings(cosmos_endpoint=""))
    fake = _FakeContainer()
    records = [_record(), _record(resource_id="/subscriptions/sub-1/rg/vm-2")]
    with patch.object(repo, "_focus_costs_container", return_value=fake):
        written = await repo.upsert_focus_records(records)
    assert written == 2
    assert fake.upserts[0]["id"] == records[0].dedup_key()
    assert fake.upserts[0]["tenant_id"] == "tenant-a"
    assert len(fake.store) == 2


async def test_upsert_focus_records_is_idempotent() -> None:
    """Re-ingesting the same identity collapses to one stored document."""
    repo = CosmosRepository(Settings(cosmos_endpoint=""))
    fake = _FakeContainer()
    first = _record(billed_cost=10.0)
    second = _record(billed_cost=99.0)  # same identity, new cost
    with patch.object(repo, "_focus_costs_container", return_value=fake):
        await repo.upsert_focus_records([first])
        await repo.upsert_focus_records([second])
    assert len(fake.upserts) == 2  # two write attempts
    assert len(fake.store) == 1  # but one logical row
    assert fake.store[first.dedup_key()]["billed_cost"] == 99.0


async def test_get_focus_records_scopes_to_tenant_partition() -> None:
    repo = CosmosRepository(Settings(cosmos_endpoint=""))
    fake = _FakeContainer([])
    with patch.object(repo, "_focus_costs_container", return_value=fake):
        await repo.get_focus_records("sub-1", "tenant-a")
    assert fake.query_calls
    assert fake.query_calls[0]["partition_key"] == "tenant-a"


async def test_get_focus_records_parses_rows() -> None:
    repo = CosmosRepository(Settings(cosmos_endpoint=""))
    doc = _record().model_dump(mode="json")
    doc["id"] = _record().dedup_key()
    fake = _FakeContainer([doc])
    with patch.object(repo, "_focus_costs_container", return_value=fake):
        out = await repo.get_focus_records("sub-1", "tenant-a")
    assert len(out) == 1
    assert out[0].sub_account_id == "sub-1"
