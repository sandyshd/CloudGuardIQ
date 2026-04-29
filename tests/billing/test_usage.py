"""Tests for cloudguardiq.billing.usage."""

from __future__ import annotations

import pytest

from cloudguardiq.billing.usage import UsageRepository, _current_period
from cloudguardiq.core.config import Settings


@pytest.mark.asyncio
async def test_get_current_returns_zero_for_new_tenant() -> None:
    repo = UsageRepository(Settings(), cosmos_db=None)
    rec = await repo.get_current("tenant-z")
    assert rec.tenant_id == "tenant-z"
    assert rec.ai_remediations == 0
    assert rec.period == _current_period()


@pytest.mark.asyncio
async def test_increment_ai_remediations_accumulates() -> None:
    repo = UsageRepository(Settings(), cosmos_db=None)
    await repo.increment_ai_remediations("tenant-a")
    await repo.increment_ai_remediations("tenant-a")
    rec = await repo.get_current("tenant-a")
    assert rec.ai_remediations == 2


@pytest.mark.asyncio
async def test_increment_isolates_by_tenant() -> None:
    repo = UsageRepository(Settings(), cosmos_db=None)
    await repo.increment_ai_remediations("tenant-a", by=3)
    await repo.increment_ai_remediations("tenant-b")
    a = await repo.get_current("tenant-a")
    b = await repo.get_current("tenant-b")
    assert a.ai_remediations == 3
    assert b.ai_remediations == 1


def test_doc_id_combines_tenant_and_period() -> None:
    from cloudguardiq.billing.usage import UsageRecord
    rec = UsageRecord(tenant_id="t1", period="2026-04")
    assert rec.doc_id == "t1:2026-04"
