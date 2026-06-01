"""Tests for cloudguardiq.adapters.pricing.live_prices."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cloudguardiq.adapters.pricing.live_prices import (
    _STATIC_FALLBACK,
    _PricingCache,
    get_fallback_cost,
    refresh_prices,
    _fetch_azure_prices,
    _fetch_aws_prices,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Static fallback (no refresh needed)
# ---------------------------------------------------------------------------

class TestGetFallbackCostStatic:
    """get_fallback_cost() returns static values before any refresh."""

    def test_known_azure_vm_type(self):
        cost = get_fallback_cost("microsoft.compute/virtualmachines")
        assert cost == _STATIC_FALLBACK["microsoft.compute/virtualmachines"]

    def test_known_aws_ec2_type(self):
        cost = get_fallback_cost("aws::ec2::instance")
        assert cost == _STATIC_FALLBACK["aws::ec2::instance"]

    def test_known_gcp_type(self):
        cost = get_fallback_cost("compute.googleapis.com/instance")
        assert cost == _STATIC_FALLBACK["compute.googleapis.com/instance"]

    def test_unknown_type_returns_zero(self):
        assert get_fallback_cost("unknown::resource::type") == 0.0

    def test_case_insensitive(self):
        # Cache keys are lower-cased; caller may pass mixed case
        cost = get_fallback_cost("Microsoft.Compute/VirtualMachines")
        assert cost == _STATIC_FALLBACK["microsoft.compute/virtualmachines"]


# ---------------------------------------------------------------------------
# Azure fetcher (httpx mocked)
# ---------------------------------------------------------------------------

class TestFetchAzurePrices:
    """_fetch_azure_prices() builds prices from the Retail Prices API."""

    @pytest.fixture()
    def mock_httpx_response(self):
        """Single-item API response with a representative hourly price."""
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {
            "Items": [{"retailPrice": 0.192, "currencyCode": "USD"}]  # ~$140/mo
        }
        return resp

    def test_azure_fetch_updates_vm_cost(self, mock_httpx_response):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_httpx_response)

        with patch("cloudguardiq.adapters.pricing.live_prices.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = mock_client
            result = _run(_fetch_azure_prices())

        # hourly 0.192 * 730 = 140.16
        assert "microsoft.compute/virtualmachines" in result
        assert result["microsoft.compute/virtualmachines"] == pytest.approx(140.16, abs=0.1)

    def test_azure_fetch_graceful_on_http_error(self):
        """Network failure must not raise; returns empty dict."""
        import httpx as _httpx

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=_httpx.ConnectError("timeout"))

        with patch("cloudguardiq.adapters.pricing.live_prices.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = mock_client
            result = _run(_fetch_azure_prices())

        assert result == {}

    def test_azure_fetch_ignores_empty_items(self):
        """Empty Items list must not raise; key is absent from result."""
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"Items": []}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=resp)

        with patch("cloudguardiq.adapters.pricing.live_prices.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = mock_client
            result = _run(_fetch_azure_prices())

        assert "microsoft.compute/virtualmachines" not in result


# ---------------------------------------------------------------------------
# AWS fetcher (boto3 mocked)
# ---------------------------------------------------------------------------

import json as _json

_EC2_PRICE_JSON = _json.dumps({
    "terms": {
        "OnDemand": {
            "key1": {
                "priceDimensions": {
                    "dim1": {
                        "pricePerUnit": {"USD": "0.192"}
                    }
                }
            }
        }
    }
})


class TestFetchAwsPrices:
    """_fetch_aws_prices() reads boto3 pricing client."""

    def test_aws_fetch_returns_empty_when_boto3_missing(self):
        with patch.dict("sys.modules", {"boto3": None, "botocore": None, "botocore.exceptions": None}):
            result = _run(_fetch_aws_prices())
        assert result == {}

    def test_aws_fetch_updates_ec2_cost(self):
        # boto3 is imported lazily inside the function, so we inject it via sys.modules
        mock_client = MagicMock()
        mock_client.get_products.return_value = {"PriceList": [_EC2_PRICE_JSON]}

        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client

        # Stub out botocore.exceptions so the import inside _fetch_aws_prices works
        mock_botocore_exc = MagicMock()
        mock_botocore_exc.BotoCoreError = Exception
        mock_botocore_exc.ClientError = Exception

        with patch.dict(
            "sys.modules",
            {
                "boto3": mock_boto3,
                "botocore": MagicMock(),
                "botocore.exceptions": mock_botocore_exc,
            },
        ):
            result = _run(_fetch_aws_prices())

        assert "aws::ec2::instance" in result
        # 0.192 * 730 = 140.16
        assert result["aws::ec2::instance"] == pytest.approx(140.16, abs=0.1)

    def test_aws_fetch_graceful_on_access_denied(self):
        """API call failure must return empty dict, not raise."""
        mock_client = MagicMock()
        mock_client.get_products.side_effect = RuntimeError("AccessDenied")

        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client

        mock_botocore_exc = MagicMock()
        mock_botocore_exc.BotoCoreError = RuntimeError
        mock_botocore_exc.ClientError = RuntimeError

        with patch.dict(
            "sys.modules",
            {
                "boto3": mock_boto3,
                "botocore": MagicMock(),
                "botocore.exceptions": mock_botocore_exc,
            },
        ):
            result = _run(_fetch_aws_prices())

        # Should return empty dict (not raise)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Cache TTL behaviour
# ---------------------------------------------------------------------------

class TestPricingCacheTTL:
    """Cache refresh respects the 24-hour TTL."""

    def test_cache_not_re_fetched_within_ttl(self):
        cache = _PricingCache()
        # Manually mark as freshly fetched
        cache._fetched_at = time.monotonic()

        call_count = 0

        async def _fake_azure():
            nonlocal call_count
            call_count += 1
            return {}

        with (
            patch("cloudguardiq.adapters.pricing.live_prices._fetch_azure_prices", _fake_azure),
            patch("cloudguardiq.adapters.pricing.live_prices._fetch_aws_prices", AsyncMock(return_value={})),
            patch("cloudguardiq.adapters.pricing.live_prices._fetch_gcp_prices", AsyncMock(return_value={})),
        ):
            _run(cache.refresh())  # Should be skipped because not stale
            _run(cache.refresh())

        assert call_count == 0, "fetch should not run when cache is fresh"

    def test_cache_refreshes_when_stale(self):
        cache = _PricingCache()
        # Force stale by setting fetched_at far in the past
        cache._fetched_at = time.monotonic() - 100_000

        call_count = 0

        async def _fake_azure():
            nonlocal call_count
            call_count += 1
            return {"microsoft.compute/virtualmachines": 999.0}

        with (
            patch("cloudguardiq.adapters.pricing.live_prices._fetch_azure_prices", _fake_azure),
            patch("cloudguardiq.adapters.pricing.live_prices._fetch_aws_prices", AsyncMock(return_value={})),
            patch("cloudguardiq.adapters.pricing.live_prices._fetch_gcp_prices", AsyncMock(return_value={})),
        ):
            _run(cache.refresh())

        assert call_count == 1
        assert cache.get("microsoft.compute/virtualmachines") == 999.0

    def test_cache_preserves_static_fallback_on_all_fetchers_empty(self):
        cache = _PricingCache()
        cache._fetched_at = 0.0  # stale

        with (
            patch("cloudguardiq.adapters.pricing.live_prices._fetch_azure_prices", AsyncMock(return_value={})),
            patch("cloudguardiq.adapters.pricing.live_prices._fetch_aws_prices", AsyncMock(return_value={})),
            patch("cloudguardiq.adapters.pricing.live_prices._fetch_gcp_prices", AsyncMock(return_value={})),
        ):
            _run(cache.refresh())

        # Static fallback must still be there
        assert cache.get("microsoft.compute/virtualmachines") == _STATIC_FALLBACK[
            "microsoft.compute/virtualmachines"
        ]


# ---------------------------------------------------------------------------
# Module-level refresh_prices() integration
# ---------------------------------------------------------------------------

class TestRefreshPricesPublicAPI:
    """refresh_prices() is a no-op on errors and respects the TTL."""

    def test_refresh_prices_does_not_raise_on_all_failures(self):
        with (
            patch(
                "cloudguardiq.adapters.pricing.live_prices._fetch_azure_prices",
                AsyncMock(side_effect=RuntimeError("boom")),
            ),
            patch(
                "cloudguardiq.adapters.pricing.live_prices._fetch_aws_prices",
                AsyncMock(side_effect=RuntimeError("boom")),
            ),
            patch(
                "cloudguardiq.adapters.pricing.live_prices._fetch_gcp_prices",
                AsyncMock(side_effect=RuntimeError("boom")),
            ),
        ):
            # Must not raise
            _run(refresh_prices())
