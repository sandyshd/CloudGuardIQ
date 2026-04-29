"""Tests for TierEnforcementMiddleware."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from cloudguardiq.billing.middleware import TierEnforcementMiddleware
from cloudguardiq.billing.repository import BillingCustomer, BillingRepository
from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import SubscriptionTier


def _build_app(
    repo: BillingRepository,
    settings: Settings,
    subscription_counter=None,
) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        TierEnforcementMiddleware,
        settings=settings,
        repository=repo,
        subscription_counter=subscription_counter,
    )

    @app.post("/scan")
    async def scan() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/subscriptions")
    async def connect() -> dict[str, str]:
        return {"status": "connected"}

    @app.get("/findings")
    async def findings() -> list[dict[str, str]]:
        return []

    return app


@pytest.mark.asyncio
async def test_free_tier_blocks_oversized_scan() -> None:
    settings = Settings(free_max_resources_per_scan=10)
    repo = BillingRepository(settings)
    app = _build_app(repo, settings)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post(
            "/scan",
            json={},
            headers={
                "X-Tenant-Id": "tenant-a",
                "X-Expected-Resource-Count": "100",
            },
        )
    assert resp.status_code == 402
    body = resp.json()
    assert body["error"] == "upgrade_required"
    assert body["current_tier"] == "free"
    assert body["limit"] == "resources_per_scan"


@pytest.mark.asyncio
async def test_free_tier_allows_small_scan() -> None:
    settings = Settings(free_max_resources_per_scan=100)
    repo = BillingRepository(settings)
    app = _build_app(repo, settings)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post(
            "/scan",
            json={},
            headers={
                "X-Tenant-Id": "tenant-a",
                "X-Expected-Resource-Count": "10",
            },
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_pro_tier_bypasses_limit() -> None:
    settings = Settings(free_max_resources_per_scan=10)
    repo = BillingRepository(settings)
    await repo.upsert(BillingCustomer(
        tenant_id="tenant-pro",
        tier=SubscriptionTier.PRO,
        stripe_customer_id="cus_1",
    ))
    app = _build_app(repo, settings)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post(
            "/scan",
            json={},
            headers={
                "X-Tenant-Id": "tenant-pro",
                "X-Expected-Resource-Count": "10000",
            },
        )
    assert resp.status_code == 200


# test_subscription_limit_blocked_for_free removed: in Phase 2 the
# /subscriptions cap check moved out of the middleware and into the
# route handler (cloudguardiq.api.subscriptions). Coverage lives in
# tests/api/test_subscriptions_routes.py::test_add_enforces_free_cap_of_1.


@pytest.mark.asyncio
async def test_unrelated_route_passes_through() -> None:
    settings = Settings(free_max_resources_per_scan=0)
    repo = BillingRepository(settings)
    app = _build_app(repo, settings)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/findings", headers={"X-Tenant-Id": "tenant-a"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_tier_cache_is_used() -> None:
    settings = Settings(free_max_resources_per_scan=10)
    repo = BillingRepository(settings)
    await repo.upsert(BillingCustomer(
        tenant_id="tenant-b", tier=SubscriptionTier.PRO,
    ))
    app = _build_app(repo, settings)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Warm the cache.
        resp1 = await ac.post(
            "/scan",
            json={},
            headers={
                "X-Tenant-Id": "tenant-b",
                "X-Expected-Resource-Count": "1000",
            },
        )
        assert resp1.status_code == 200

        # Downgrade the record in the DB. Cache should still honor PRO.
        await repo.upsert(BillingCustomer(
            tenant_id="tenant-b", tier=SubscriptionTier.FREE,
        ))
        resp2 = await ac.post(
            "/scan",
            json={},
            headers={
                "X-Tenant-Id": "tenant-b",
                "X-Expected-Resource-Count": "1000",
            },
        )
        assert resp2.status_code == 200
