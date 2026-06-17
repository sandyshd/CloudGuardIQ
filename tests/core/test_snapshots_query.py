"""Tests for snapshot read path (Resources page backend).

Verifies the pure query builder and the read-time normaliser used by
``CosmosRepository.get_snapshots`` so the /resources endpoint stays
tenant-scoped and resilient to legacy rows.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from cloudguardiq.core.config import Settings
from cloudguardiq.core.database import (
    CosmosRepository,
    _build_snapshots_query,
    _normalise_snapshot_doc,
)


class _FakeContainer:
    """Minimal async Cosmos container stub recording query_items calls."""

    def __init__(self, items: list[dict[str, Any]]) -> None:
        self._items = items
        self.calls: list[dict[str, Any]] = []

    def query_items(
        self,
        *,
        query: str,
        parameters: list[dict[str, Any]] | None = None,
        partition_key: Any = None,
    ) -> Any:
        self.calls.append(
            {
                "query": query,
                "parameters": parameters,
                "partition_key": partition_key,
            }
        )
        items = self._items

        async def _gen() -> Any:
            for item in items:
                yield item

        return _gen()


def test_build_snapshots_query_filters_by_tenant_and_sub() -> None:
    query, params = _build_snapshots_query(
        tenant_id="tenant-A", subscription_id="sub-1", limit=25
    )
    assert "c.tenant_id = @tenant_id" in query
    assert "c.subscription_id = @sub_id" in query
    names = {p["name"] for p in params}
    assert {"@tenant_id", "@sub_id", "@limit"} <= names


def test_build_snapshots_query_without_tenant_drops_filter() -> None:
    """Legacy/dev mode: empty tenant_id degrades to sub-only filter."""
    query, _ = _build_snapshots_query(
        tenant_id="", subscription_id="sub-1", limit=10
    )
    assert "c.tenant_id" not in query
    assert "c.subscription_id = @sub_id" in query


def test_build_snapshots_query_orders_by_cost_desc() -> None:
    query, _ = _build_snapshots_query(
        tenant_id="tenant-A", subscription_id="sub-1", limit=10
    )
    assert "ORDER BY c.cost_monthly DESC" in query


def test_normalise_snapshot_doc_restores_canonical_id() -> None:
    """The canonical id lives in resource_id; the storage id is Cosmos-safe."""
    doc = {
        "id": "deadbeef-hash",
        "resource_id": "azure/storageaccounts/sub/rg/sa",
        "subscription_id": "sub-1",
        "resource_group": "rg",
        "resource_type": "Microsoft.Storage/storageAccounts",
        "resource_name": "sa",
        "region": "eastus",
        "provider": "AZURE",
        "data_tier": "TIER1_NATIVE",
    }
    out = _normalise_snapshot_doc(doc)
    assert out["id"] == "azure/storageaccounts/sub/rg/sa"


def test_normalise_snapshot_doc_null_guards_legacy_fields() -> None:
    doc = {
        "id": "x",
        "resource_id": "azure/x/sub/rg/n",
        "subscription_id": "sub-1",
        "resource_group": None,
        "resource_type": "t",
        "resource_name": "n",
        "region": None,
        "provider": "AZURE",
        "data_tier": "TIER1_NATIVE",
        "config": None,
        "tags": None,
    }
    out = _normalise_snapshot_doc(doc)
    assert out["resource_group"] == ""
    assert out["region"] == ""
    assert out["config"] == {}
    assert out["tags"] == {}


async def test_get_snapshots_scopes_to_subscription_partition() -> None:
    """get_snapshots must run a single-partition query for the subscription.

    snapshots is partitioned by /subscription_id, so the read path must pass
    partition_key=subscription_id rather than fanning out cross-partition.
    """
    repo = CosmosRepository(Settings(cosmos_endpoint=""))
    fake = _FakeContainer([])
    with patch.object(repo, "_snapshots_container", return_value=fake):
        await repo.get_snapshots("sub-1", tenant_id="tenant-A")
    assert fake.calls, "query_items was never called"
    assert fake.calls[0]["partition_key"] == "sub-1"
