"""Phase 2.7: soft-delete retention behaviour for subscriptions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

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
async def test_hard_delete_bypasses_soft_state(
    repo: SubscriptionsRepository,
) -> None:
    sid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    await repo.upsert(SubscriptionRecord(tenant_id="A", subscription_id=sid))
    assert await repo.hard_delete("A", sid) is True
    assert await repo.get("A", sid) is None


@pytest.mark.asyncio
async def test_list_expired_removed_only_returns_old_records(
    repo: SubscriptionsRepository,
) -> None:
    sid_old = "11111111-1111-1111-1111-111111111111"
    sid_new = "22222222-2222-2222-2222-222222222222"
    await repo.upsert(SubscriptionRecord(
        tenant_id="A",
        subscription_id=sid_old,
        state="Removed",
        removed_at=datetime.now(timezone.utc) - timedelta(days=45),
    ))
    await repo.upsert(SubscriptionRecord(
        tenant_id="A",
        subscription_id=sid_new,
        state="Removed",
        removed_at=datetime.now(timezone.utc) - timedelta(days=2),
    ))
    expired = await repo.list_expired_removed(retention_days=30)
    ids = {r.subscription_id for r in expired}
    assert sid_old in ids
    assert sid_new not in ids


@pytest.mark.asyncio
async def test_include_removed_returns_all(
    repo: SubscriptionsRepository,
) -> None:
    sid = "33333333-3333-3333-3333-333333333333"
    await repo.upsert(SubscriptionRecord(tenant_id="A", subscription_id=sid))
    await repo.delete("A", sid)
    assert await repo.list("A") == []
    full = await repo.list("A", include_removed=True)
    assert len(full) == 1
    assert full[0].state == "Removed"
