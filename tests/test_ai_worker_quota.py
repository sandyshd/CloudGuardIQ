"""Tests for AIWorker plan-tier quota enforcement (Phase 2.5)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from cloudguardiq.billing.repository import BillingCustomer, BillingRepository
from cloudguardiq.billing.usage import UsageRepository
from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import DataTier, Severity, SubscriptionTier
from cloudguardiq.core.models import FindingResult, RemediationCard, ResourceSnapshot
from cloudguardiq.pipeline.ai_worker import AIWorker


def _finding(tenant_id: str = "tenant-a") -> FindingResult:
    return FindingResult(
        tenant_id=tenant_id,
        rule_id="STORAGE-001",
        rule_name="HTTPS only",
        severity=Severity.HIGH,
        description="x",
        resource_snapshot=ResourceSnapshot(
            tenant_id=tenant_id,
            subscription_id="sub-1",
            resource_group="rg",
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="acct",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
        ),
    )


def _card(finding: FindingResult) -> RemediationCard:
    return RemediationCard(
        finding_result=finding,
        narrative="fix",
        terraform_fix="resource {}",
        cli_fix="az ...",
    )


def _mock_engine(card: RemediationCard) -> MagicMock:
    engine = MagicMock()
    engine.generate = AsyncMock(return_value=card)
    return engine


def _mock_db() -> MagicMock:
    db = MagicMock()
    db.save_remediation_card = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_worker_blocks_when_free_tenant_over_cap() -> None:
    settings = Settings()
    billing = BillingRepository(settings)
    usage = UsageRepository(settings)
    # FREE cap = 5, exhaust it.
    for _ in range(5):
        await usage.increment_ai_remediations("tenant-a")

    finding = _finding("tenant-a")
    engine = _mock_engine(_card(finding))
    worker = AIWorker(
        ai_engine=engine, db=_mock_db(),
        billing_repo=billing, usage_repo=usage,
    )
    result = await worker.process_message(json.dumps(finding.model_dump(mode="json")))
    assert result is None
    engine.generate.assert_not_called()


@pytest.mark.asyncio
async def test_worker_allows_under_cap_and_increments() -> None:
    settings = Settings()
    billing = BillingRepository(settings)
    usage = UsageRepository(settings)

    finding = _finding("tenant-b")
    card = _card(finding)
    engine = _mock_engine(card)
    worker = AIWorker(
        ai_engine=engine, db=_mock_db(),
        billing_repo=billing, usage_repo=usage,
    )
    out = await worker.process_message(json.dumps(finding.model_dump(mode="json")))
    assert out is card
    rec = await usage.get_current("tenant-b")
    assert rec.ai_remediations == 1


@pytest.mark.asyncio
async def test_worker_pro_higher_cap() -> None:
    settings = Settings()
    billing = BillingRepository(settings)
    await billing.upsert(BillingCustomer(
        tenant_id="tenant-pro", tier=SubscriptionTier.PRO,
    ))
    usage = UsageRepository(settings)
    # FREE cap (5) is exceeded but PRO cap (100) is not.
    for _ in range(20):
        await usage.increment_ai_remediations("tenant-pro")

    finding = _finding("tenant-pro")
    engine = _mock_engine(_card(finding))
    worker = AIWorker(
        ai_engine=engine, db=_mock_db(),
        billing_repo=billing, usage_repo=usage,
    )
    result = await worker.process_message(json.dumps(finding.model_dump(mode="json")))
    assert result is not None
    engine.generate.assert_called_once()


@pytest.mark.asyncio
async def test_worker_without_repos_skips_quota_check() -> None:
    """Backward compatibility: omitted repos -> no enforcement."""
    finding = _finding("tenant-c")
    engine = _mock_engine(_card(finding))
    worker = AIWorker(ai_engine=engine, db=_mock_db())
    result = await worker.process_message(json.dumps(finding.model_dump(mode="json")))
    assert result is not None
    engine.generate.assert_called_once()
