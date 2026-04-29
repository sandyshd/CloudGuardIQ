"""Phase 2: SubscriptionsRepository tests (in-memory fallback)."""

from __future__ import annotations

import pytest

from cloudguardiq.core.config import Settings
from cloudguardiq.subscriptions.repository import (
    SubscriptionRecord,
    SubscriptionsRepository,
)


@pytest.fixture
def repo() -> SubscriptionsRepository:
    return SubscriptionsRepository(Settings(), cosmos_db=None)


@pytest.mark.asyncio
async def test_repo_starts_empty(repo: SubscriptionsRepository) -> None:
    assert await repo.list("tenant-A") == []
    assert await repo.count("tenant-A") == 0


@pytest.mark.asyncio
async def test_repo_upsert_and_get(repo: SubscriptionsRepository) -> None:
    rec = SubscriptionRecord(
        tenant_id="tenant-A",
        subscription_id="11111111-1111-1111-1111-111111111111",
        display_name="Prod",
    )
    saved = await repo.upsert(rec)
    assert saved.tenant_id == "tenant-A"
    assert saved.added_at is not None
    fetched = await repo.get("tenant-A", saved.subscription_id)
    assert fetched is not None
    assert fetched.display_name == "Prod"


@pytest.mark.asyncio
async def test_repo_count_isolates_tenants(repo: SubscriptionsRepository) -> None:
    await repo.upsert(SubscriptionRecord(
        tenant_id="A", subscription_id="11111111-1111-1111-1111-111111111111",
    ))
    await repo.upsert(SubscriptionRecord(
        tenant_id="B", subscription_id="22222222-2222-2222-2222-222222222222",
    ))
    await repo.upsert(SubscriptionRecord(
        tenant_id="B", subscription_id="33333333-3333-3333-3333-333333333333",
    ))
    assert await repo.count("A") == 1
    assert await repo.count("B") == 2


@pytest.mark.asyncio
async def test_repo_delete(repo: SubscriptionsRepository) -> None:
    sid = "11111111-1111-1111-1111-111111111111"
    await repo.upsert(SubscriptionRecord(tenant_id="A", subscription_id=sid))
    assert await repo.delete("A", sid) is True
    assert await repo.get("A", sid) is None
    # Idempotent
    assert await repo.delete("A", sid) is False


@pytest.mark.asyncio
async def test_repo_list_returns_only_own_tenant(repo: SubscriptionsRepository) -> None:
    await repo.upsert(SubscriptionRecord(
        tenant_id="A", subscription_id="11111111-1111-1111-1111-111111111111",
    ))
    await repo.upsert(SubscriptionRecord(
        tenant_id="B", subscription_id="22222222-2222-2222-2222-222222222222",
    ))
    a = await repo.list("A")
    b = await repo.list("B")
    assert {r.tenant_id for r in a} == {"A"}
    assert {r.tenant_id for r in b} == {"B"}
