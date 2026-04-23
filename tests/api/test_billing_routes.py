"""Tests for billing API routes."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from cloudguardiq.api import billing as billing_module
from cloudguardiq.api.main import app
from cloudguardiq.billing.repository import BillingCustomer, BillingRepository
from cloudguardiq.billing.stripe_service import StripeService, StripeServiceError
from cloudguardiq.core.config import get_settings
from cloudguardiq.core.enums import SubscriptionTier


@pytest.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def fresh_repo() -> BillingRepository:
    return BillingRepository(get_settings(), cosmos_db=None)


@pytest.mark.asyncio
async def test_status_defaults_to_free(
    client: AsyncClient, fresh_repo: BillingRepository,
) -> None:
    stripe = StripeService(get_settings())
    billing_module.configure(repository=fresh_repo, stripe_service=stripe)
    resp = await client.get("/billing/status")
    assert resp.status_code == 200
    assert resp.json()["tier"] == SubscriptionTier.FREE.value


@pytest.mark.asyncio
async def test_status_returns_persisted_tier(
    client: AsyncClient, fresh_repo: BillingRepository,
) -> None:
    await fresh_repo.upsert(BillingCustomer(
        tenant_id="anonymous",
        tier=SubscriptionTier.PRO,
        stripe_customer_id="cus_1",
        stripe_subscription_id="sub_1",
    ))
    stripe = StripeService(get_settings())
    billing_module.configure(repository=fresh_repo, stripe_service=stripe)
    resp = await client.get("/billing/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] == SubscriptionTier.PRO.value
    assert body["stripe_customer_id"] == "cus_1"


@pytest.mark.asyncio
async def test_checkout_creates_session(
    client: AsyncClient, fresh_repo: BillingRepository,
) -> None:
    stripe = StripeService(get_settings())
    stripe.ensure_customer = AsyncMock(return_value="cus_new")  # type: ignore[method-assign]
    stripe.create_checkout_session = AsyncMock(  # type: ignore[method-assign]
        return_value="https://stripe.example/abc",
    )
    stripe.price_id_for_tier = lambda tier: "price_pro"  # type: ignore[method-assign]
    billing_module.configure(repository=fresh_repo, stripe_service=stripe)

    resp = await client.post("/billing/checkout", json={"tier": "PRO"})
    assert resp.status_code == 200
    assert resp.json()["url"] == "https://stripe.example/abc"

    stored = await fresh_repo.get("anonymous")
    assert stored is not None
    assert stored.stripe_customer_id == "cus_new"


@pytest.mark.asyncio
async def test_checkout_rejects_free_tier(
    client: AsyncClient, fresh_repo: BillingRepository,
) -> None:
    billing_module.configure(
        repository=fresh_repo,
        stripe_service=StripeService(get_settings()),
    )
    resp = await client.post("/billing/checkout", json={"tier": "FREE"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_webhook_requires_signature(
    client: AsyncClient, fresh_repo: BillingRepository,
) -> None:
    billing_module.configure(
        repository=fresh_repo,
        stripe_service=StripeService(get_settings()),
    )
    resp = await client.post("/billing/webhook", content=b"{}")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_webhook_invalid_signature(
    client: AsyncClient, fresh_repo: BillingRepository,
) -> None:
    stripe = StripeService(get_settings())
    stripe.verify_webhook = lambda **kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        StripeServiceError("bad"),
    )
    billing_module.configure(repository=fresh_repo, stripe_service=stripe)
    resp = await client.post(
        "/billing/webhook",
        content=b"{}",
        headers={"Stripe-Signature": "sig"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_webhook_subscription_updated(
    client: AsyncClient, fresh_repo: BillingRepository,
) -> None:
    await fresh_repo.upsert(BillingCustomer(
        tenant_id="tenant-x",
        stripe_customer_id="cus_9",
        tier=SubscriptionTier.FREE,
    ))
    stripe = StripeService(get_settings())
    event = {
        "type": "customer.subscription.updated",
        "data": {"object": {
            "id": "sub_9",
            "customer": "cus_9",
            "items": {"data": [{"price": {"id": "price_pro"}}]},
        }},
    }
    stripe.verify_webhook = lambda **kwargs: event  # type: ignore[method-assign]
    stripe.tier_for_price_id = lambda pid: SubscriptionTier.PRO  # type: ignore[method-assign]
    billing_module.configure(repository=fresh_repo, stripe_service=stripe)

    resp = await client.post(
        "/billing/webhook",
        content=b"{}",
        headers={"Stripe-Signature": "sig"},
    )
    assert resp.status_code == 200
    stored = await fresh_repo.get("tenant-x")
    assert stored is not None
    assert stored.tier == SubscriptionTier.PRO
    assert stored.stripe_subscription_id == "sub_9"


@pytest.mark.asyncio
async def test_webhook_subscription_deleted(
    client: AsyncClient, fresh_repo: BillingRepository,
) -> None:
    await fresh_repo.upsert(BillingCustomer(
        tenant_id="tenant-y",
        stripe_customer_id="cus_10",
        stripe_subscription_id="sub_10",
        tier=SubscriptionTier.PRO,
    ))
    stripe = StripeService(get_settings())
    event = {
        "type": "customer.subscription.deleted",
        "data": {"object": {"id": "sub_10", "customer": "cus_10"}},
    }
    stripe.verify_webhook = lambda **kwargs: event  # type: ignore[method-assign]
    billing_module.configure(repository=fresh_repo, stripe_service=stripe)

    resp = await client.post(
        "/billing/webhook",
        content=b"{}",
        headers={"Stripe-Signature": "sig"},
    )
    assert resp.status_code == 200
    stored = await fresh_repo.get("tenant-y")
    assert stored is not None
    assert stored.tier == SubscriptionTier.FREE
    assert stored.stripe_subscription_id == ""
