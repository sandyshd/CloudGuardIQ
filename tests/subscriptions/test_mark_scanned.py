"""Tests for SubscriptionsRepository.mark_scanned (Phase 2.5)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cloudguardiq.core.config import Settings
from cloudguardiq.subscriptions.repository import (
    SubscriptionRecord,
    SubscriptionsRepository,
)


@pytest.mark.asyncio
async def test_mark_scanned_stamps_last_scan_at() -> None:
    repo = SubscriptionsRepository(Settings(), cosmos_db=None)
    await repo.upsert(SubscriptionRecord(
        tenant_id="t1",
        subscription_id="00000000-0000-0000-0000-000000000001",
    ))
    before = datetime.now(timezone.utc) - timedelta(seconds=1)
    updated = await repo.mark_scanned(
        "t1", "00000000-0000-0000-0000-000000000001",
    )
    assert updated is not None
    assert updated.last_scan_at is not None
    assert updated.last_scan_at >= before


@pytest.mark.asyncio
async def test_mark_scanned_returns_none_when_missing() -> None:
    repo = SubscriptionsRepository(Settings(), cosmos_db=None)
    out = await repo.mark_scanned("ghost", "11111111-1111-1111-1111-111111111111")
    assert out is None
