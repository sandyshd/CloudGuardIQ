"""Tests for StripeService."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cloudguardiq.billing.stripe_service import StripeService, StripeServiceError
from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import SubscriptionTier


def _settings() -> Settings:
    return Settings(
        stripe_api_key="sk_test_dummy",
        stripe_webhook_secret="whsec_dummy",
        stripe_price_free="price_free",
        stripe_price_pro="price_pro",
        stripe_price_enterprise="price_ent",
    )


class TestPriceMapping:
    def test_price_for_tier(self) -> None:
        svc = StripeService(_settings())
        assert svc.price_id_for_tier(SubscriptionTier.PRO) == "price_pro"
        assert svc.price_id_for_tier(SubscriptionTier.ENTERPRISE) == "price_ent"

    def test_price_missing_raises(self) -> None:
        settings = _settings()
        settings.stripe_price_pro = ""
        svc = StripeService(settings)
        with pytest.raises(StripeServiceError):
            svc.price_id_for_tier(SubscriptionTier.PRO)

    def test_tier_for_price(self) -> None:
        svc = StripeService(_settings())
        assert svc.tier_for_price_id("price_ent") == SubscriptionTier.ENTERPRISE
        assert svc.tier_for_price_id("price_pro") == SubscriptionTier.PRO
        assert svc.tier_for_price_id("unknown") == SubscriptionTier.FREE


class TestEnsureCustomer:
    @pytest.mark.asyncio
    async def test_returns_existing(self) -> None:
        svc = StripeService(_settings())
        result = await svc.ensure_customer(
            tenant_id="t1", existing_customer_id="cus_123",
        )
        assert result == "cus_123"

    @pytest.mark.asyncio
    async def test_creates_new(self) -> None:
        svc = StripeService(_settings())
        with patch(
            "cloudguardiq.billing.stripe_service._stripe",
        ) as mock_stripe:
            mock_stripe.Customer.create.return_value = {"id": "cus_new"}
            result = await svc.ensure_customer(
                tenant_id="t1", email="t@example.com",
            )
        assert result == "cus_new"


class TestCheckout:
    @pytest.mark.asyncio
    async def test_returns_url(self) -> None:
        svc = StripeService(_settings())
        with patch(
            "cloudguardiq.billing.stripe_service._stripe",
        ) as mock_stripe:
            mock_stripe.checkout.Session.create.return_value = {
                "url": "https://stripe.example/session",
            }
            url = await svc.create_checkout_session(
                customer_id="cus_1", price_id="price_pro",
            )
        assert url == "https://stripe.example/session"

    @pytest.mark.asyncio
    async def test_no_url_raises(self) -> None:
        svc = StripeService(_settings())
        with patch(
            "cloudguardiq.billing.stripe_service._stripe",
        ) as mock_stripe:
            mock_stripe.checkout.Session.create.return_value = {}
            with pytest.raises(StripeServiceError):
                await svc.create_checkout_session(
                    customer_id="cus_1", price_id="price_pro",
                )


class TestSubscriptionStatus:
    @pytest.mark.asyncio
    async def test_no_subscription_is_free(self) -> None:
        svc = StripeService(_settings())
        with patch(
            "cloudguardiq.billing.stripe_service._stripe",
        ) as mock_stripe:
            mock_stripe.Subscription.list.return_value = {"data": []}
            tier = await svc.get_subscription_status("cus_1")
        assert tier == SubscriptionTier.FREE

    @pytest.mark.asyncio
    async def test_active_pro_subscription(self) -> None:
        svc = StripeService(_settings())
        with patch(
            "cloudguardiq.billing.stripe_service._stripe",
        ) as mock_stripe:
            mock_stripe.Subscription.list.return_value = {
                "data": [{
                    "items": {
                        "data": [{"price": {"id": "price_pro"}}],
                    },
                }],
            }
            tier = await svc.get_subscription_status("cus_1")
        assert tier == SubscriptionTier.PRO

    @pytest.mark.asyncio
    async def test_network_error_returns_free(self) -> None:
        svc = StripeService(_settings())
        with patch(
            "cloudguardiq.billing.stripe_service._stripe",
        ) as mock_stripe:
            mock_stripe.Subscription.list.side_effect = RuntimeError("boom")
            tier = await svc.get_subscription_status("cus_1")
        assert tier == SubscriptionTier.FREE


class TestWebhook:
    def test_missing_secret_raises(self) -> None:
        settings = _settings()
        settings.stripe_webhook_secret = ""
        svc = StripeService(settings)
        with pytest.raises(StripeServiceError):
            svc.verify_webhook(payload=b"{}", signature="sig")

    def test_invalid_signature_raises(self) -> None:
        svc = StripeService(_settings())
        mock_module = MagicMock()
        mock_module.Webhook.construct_event.side_effect = ValueError("bad sig")
        with patch(
            "cloudguardiq.billing.stripe_service._stripe", mock_module,
        ), pytest.raises(StripeServiceError):
            svc.verify_webhook(payload=b"{}", signature="sig")

    def test_valid_signature_returns_event(self) -> None:
        svc = StripeService(_settings())
        event = {"type": "customer.subscription.updated", "data": {"object": {}}}
        mock_module = MagicMock()
        mock_module.Webhook.construct_event.return_value = event
        with patch(
            "cloudguardiq.billing.stripe_service._stripe", mock_module,
        ):
            result = svc.verify_webhook(payload=b"{}", signature="sig")
        assert result["type"] == "customer.subscription.updated"
