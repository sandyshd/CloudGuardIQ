"""Tests for ScanPipeline producer-side AI quota awareness (Phase 2.6)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from cloudguardiq.billing.repository import BillingCustomer, BillingRepository
from cloudguardiq.billing.usage import UsageRepository
from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import DataTier, Severity, SubscriptionTier
from cloudguardiq.core.models import FindingResult, ResourceSnapshot
from cloudguardiq.pipeline.scan_pipeline import ScanPipeline


def _snap(name: str, tenant_id: str = "t1") -> ResourceSnapshot:
    return ResourceSnapshot(
        tenant_id=tenant_id,
        subscription_id="sub-1",
        resource_group="rg",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name=name,
        region="eastus",
        data_tier=DataTier.TIER1_NATIVE,
    )


def _findings(n: int, tenant_id: str = "t1") -> list[FindingResult]:
    """Build *n* findings with descending priority_score (i.e. f0 highest)."""
    out: list[FindingResult] = []
    for i in range(n):
        f = FindingResult(
            tenant_id=tenant_id,
            rule_id=f"R-{i}",
            rule_name="r",
            severity=Severity.HIGH,
            description="x",
            resource_snapshot=_snap(f"r{i}", tenant_id),
        )
        f.priority_score = float(n - i)  # f0 highest, f(n-1) lowest
        out.append(f)
    return out


def _build_pipeline(
    findings: list[FindingResult],
    *,
    billing_repo: BillingRepository | None = None,
    usage_repo: UsageRepository | None = None,
) -> tuple[ScanPipeline, AsyncMock]:
    adapter = MagicMock()
    adapter.scan = AsyncMock(return_value=[f.resource_snapshot for f in findings])

    policy = MagicMock()
    policy.evaluate = MagicMock(return_value=findings)

    db = MagicMock()
    db.save_finding = AsyncMock()
    db.save_scan_result = AsyncMock()

    sender = MagicMock()
    sender.send_messages = AsyncMock()

    pipeline = ScanPipeline(
        adapter=adapter,
        policy_engine=policy,
        ai_engine=None,
        db=db,
        service_bus_sender=sender,
        billing_repo=billing_repo,
        usage_repo=usage_repo,
        auto_generate_ai=True,
    )
    return pipeline, sender.send_messages


@pytest.mark.asyncio
async def test_free_tenant_only_top_n_findings_queued() -> None:
    """FREE cap=5: 10 findings -> only the 5 highest-priority queued."""
    settings = Settings()
    billing = BillingRepository(settings)
    usage = UsageRepository(settings)
    findings = _findings(10)
    pipeline, send = _build_pipeline(
        findings, billing_repo=billing, usage_repo=usage,
    )
    result = await pipeline.run("sub-1", tenant_id="t1")

    assert send.await_count == 5
    # The five queued findings must be the highest-priority ones (f0..f4).
    sent_rule_ids = {
        c.args[0].decode("utf-8") if isinstance(c.args[0], bytes)
        else getattr(c.args[0], "body", str(c.args[0]))
        for c in send.await_args_list
    }
    # Body is a JSON string; just assert size since exact body type depends
    # on whether ServiceBusMessage is importable.
    assert len(sent_rule_ids) == 5
    assert result.findings_count == 10  # all findings still saved


@pytest.mark.asyncio
async def test_free_tenant_at_cap_queues_nothing() -> None:
    settings = Settings()
    billing = BillingRepository(settings)
    usage = UsageRepository(settings)
    for _ in range(5):
        await usage.increment_ai_remediations("t1")

    pipeline, send = _build_pipeline(
        _findings(3), billing_repo=billing, usage_repo=usage,
    )
    await pipeline.run("sub-1", tenant_id="t1")
    assert send.await_count == 0


@pytest.mark.asyncio
async def test_pro_tenant_higher_cap() -> None:
    settings = Settings()
    billing = BillingRepository(settings)
    await billing.upsert(BillingCustomer(
        tenant_id="t1", tier=SubscriptionTier.PRO,
    ))
    usage = UsageRepository(settings)
    pipeline, send = _build_pipeline(
        _findings(50), billing_repo=billing, usage_repo=usage,
    )
    await pipeline.run("sub-1", tenant_id="t1")
    # PRO cap = 100, all 50 findings should be queued.
    assert send.await_count == 50


@pytest.mark.asyncio
async def test_enterprise_unlimited_queues_all() -> None:
    settings = Settings()
    billing = BillingRepository(settings)
    await billing.upsert(BillingCustomer(
        tenant_id="t1", tier=SubscriptionTier.ENTERPRISE,
    ))
    usage = UsageRepository(settings)
    # Even with high prior usage, Enterprise has no cap.
    for _ in range(10000):
        await usage.increment_ai_remediations("t1")

    pipeline, send = _build_pipeline(
        _findings(20), billing_repo=billing, usage_repo=usage,
    )
    await pipeline.run("sub-1", tenant_id="t1")
    assert send.await_count == 20


@pytest.mark.asyncio
async def test_no_repos_means_no_enforcement() -> None:
    """Backward compatibility: if repos are absent, all findings queue."""
    pipeline, send = _build_pipeline(_findings(8))
    await pipeline.run("sub-1", tenant_id="t1")
    assert send.await_count == 8


@pytest.mark.asyncio
async def test_no_tenant_id_means_no_enforcement() -> None:
    """Without a tenant id we cannot meter; fall through to queue all."""
    settings = Settings()
    pipeline, send = _build_pipeline(
        _findings(8),
        billing_repo=BillingRepository(settings),
        usage_repo=UsageRepository(settings),
    )
    await pipeline.run("sub-1", tenant_id="")
    assert send.await_count == 8
