"""Phase 2: SubscriptionsRepository tests (in-memory fallback)."""

from __future__ import annotations

import pytest

from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import CloudProvider
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
async def test_repo_delete_is_soft(repo: SubscriptionsRepository) -> None:
    sid = "11111111-1111-1111-1111-111111111111"
    await repo.upsert(SubscriptionRecord(tenant_id="A", subscription_id=sid))
    assert await repo.delete("A", sid) is True
    # Soft delete keeps the row but marks it Removed and stamps removed_at
    rec = await repo.get("A", sid)
    assert rec is not None
    assert rec.state == "Removed"
    assert rec.removed_at is not None
    # Tier-cap-relevant views must hide it
    assert await repo.list("A") == []
    assert await repo.count("A") == 0
    # Idempotent: second delete on a Removed record returns False
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


def test_aws_role_fields_default_empty() -> None:
    """New records default the AWS assume-role fields to empty strings."""
    rec = SubscriptionRecord(
        tenant_id="A",
        subscription_id="123456789012",
    )
    assert rec.aws_role_arn == ""
    assert rec.aws_external_id == ""


def test_aws_role_fields_round_trip() -> None:
    """aws_role_arn / aws_external_id survive a to_document/from_document cycle."""
    rec = SubscriptionRecord(
        tenant_id="A",
        subscription_id="123456789012",
        provider=CloudProvider.AWS,
        aws_account_id="123456789012",
        aws_region="us-east-1",
        aws_role_arn="arn:aws:iam::123456789012:role/CloudGuardIQScanner",
        aws_external_id="cgiq-abc123",
    )
    doc = rec.to_document()
    assert doc["aws_role_arn"] == "arn:aws:iam::123456789012:role/CloudGuardIQScanner"
    assert doc["aws_external_id"] == "cgiq-abc123"

    restored = SubscriptionRecord.from_document(doc)
    assert restored.aws_role_arn == rec.aws_role_arn
    assert restored.aws_external_id == rec.aws_external_id


def test_from_document_missing_aws_role_fields_defaults_empty() -> None:
    """Legacy documents without the AWS assume-role keys deserialise to ''."""
    legacy = {
        "tenant_id": "A",
        "subscription_id": "123456789012",
        "provider": "AWS",
        "aws_account_id": "123456789012",
    }
    restored = SubscriptionRecord.from_document(legacy)
    assert restored.aws_role_arn == ""
    assert restored.aws_external_id == ""
