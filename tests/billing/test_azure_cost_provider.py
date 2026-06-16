"""Tests for AzureCostProvider (Prompt 1).

All Azure SDK and HTTP calls are mocked -- no network, no credentials.
"""

from __future__ import annotations

from typing import Any

import pytest

from cloudguardiq.billing.azure_cost_provider import AzureCostProvider
from cloudguardiq.billing.pricing import PricingService
from cloudguardiq.core.enums import DataTier


class _FakeRows:
    def __init__(self, rows: list[list[Any]]) -> None:
        self.rows = rows


class _FakeQueryUsage:
    """Mimics client.query.usage(scope, query_def) -> object with .rows."""

    def __init__(self, rows: list[list[Any]] | None = None, *, raises: Exception | None = None) -> None:
        self._rows = rows or []
        self._raises = raises
        self.calls = 0

    def __call__(self, scope: str, query_def: Any) -> _FakeRows:
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return _FakeRows(self._rows)


class _FakeQuery:
    def __init__(self, usage: _FakeQueryUsage) -> None:
        self.usage = usage


class _FakeCostClient:
    def __init__(self, usage: _FakeQueryUsage) -> None:
        self.query = _FakeQuery(usage)


def _provider_with_rows(rows, *, raises=None, pricing=None):
    usage = _FakeQueryUsage(rows, raises=raises)
    return (
        AzureCostProvider(
            credential=object(),
            subscription_id="sub-123",
            pricing_service=pricing or PricingService(),
            client_factory=lambda cred: _FakeCostClient(usage),
        ),
        usage,
    )


@pytest.mark.asyncio
class TestActualCost:
    async def test_maps_resource_ids_to_monthly_cost(self) -> None:
        rows = [
            [42.50, "/subscriptions/sub-123/RG/A"],
            [10.00, "/subscriptions/sub-123/RG/B"],
        ]
        prov, _ = _provider_with_rows(rows)
        out = await prov.get_actual_cost(
            ["/subscriptions/sub-123/RG/A", "/subscriptions/sub-123/RG/B"]
        )
        assert out == {
            "/subscriptions/sub-123/rg/a": 42.50,
            "/subscriptions/sub-123/rg/b": 10.00,
        }

    async def test_empty_resource_ids_short_circuits(self) -> None:
        prov, usage = _provider_with_rows([])
        assert await prov.get_actual_cost([]) == {}
        assert usage.calls == 0

    async def test_api_failure_degrades_to_empty(self) -> None:
        prov, _ = _provider_with_rows([], raises=RuntimeError("Cost API down"))
        assert await prov.get_actual_cost(["/subscriptions/sub-123/RG/A"]) == {}

    async def test_no_credential_returns_empty(self) -> None:
        prov = AzureCostProvider(
            credential=None,
            subscription_id="sub-123",
            pricing_service=PricingService(),
        )
        assert await prov.get_actual_cost(["/x"]) == {}

    async def test_actual_cost_tier_is_enriched(self) -> None:
        prov, _ = _provider_with_rows([])
        assert prov.actual_cost_tier == DataTier.TIER2_ENRICHED


@pytest.mark.asyncio
class TestListPrice:
    async def test_returns_cached_price(self) -> None:
        pricing = PricingService()
        pricing._cache[("public_ip_standard", "eastus")] = 3.65  # noqa: SLF001
        prov, _ = _provider_with_rows([], pricing=pricing)
        assert await prov.get_list_price("public_ip_standard", "eastus") == 3.65

    async def test_miss_returns_default(self) -> None:
        prov, _ = _provider_with_rows([], pricing=PricingService())
        assert await prov.get_list_price("nope", "eastus", default=9.0) == 9.0

    async def test_miss_returns_zero_without_default(self) -> None:
        prov, _ = _provider_with_rows([], pricing=PricingService())
        assert await prov.get_list_price("nope", "eastus") == 0.0


@pytest.mark.asyncio
class TestRightsizing:
    async def test_savings_is_price_delta(self) -> None:
        pricing = PricingService()
        # Seed the on-demand VM-size cache with live-style prices.
        pricing._cache[("vm_Standard_D4s_v3", "eastus")] = 280.0  # noqa: SLF001
        pricing._cache[("vm_Standard_D2s_v3", "eastus")] = 140.0  # noqa: SLF001
        prov, _ = _provider_with_rows([], pricing=pricing)
        savings = await prov.estimate_vm_rightsizing_savings(
            "Standard_D4s_v3", "eastus"
        )
        assert savings == 140.0

    async def test_unknown_size_returns_zero(self) -> None:
        prov, _ = _provider_with_rows([], pricing=PricingService())
        assert await prov.estimate_vm_rightsizing_savings("Standard_Unknown", "eastus") == 0.0

    async def test_missing_price_returns_zero(self) -> None:
        # Pricing service whose on-demand fetch always misses (empty Items),
        # so the smaller-size price is unavailable -> savings 0.0. The current
        # size is pre-seeded; only the smaller lookup hits the (miss) session.
        class _MissResp:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return None

            async def json(self):
                return {"Items": []}

        class _MissSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return None

            def get(self, url, params=None, timeout=None):
                return _MissResp()

        pricing = PricingService(session_factory=lambda: _MissSession())
        pricing._cache[("vm_Standard_D4s_v3", "eastus")] = 280.0  # noqa: SLF001
        prov, _ = _provider_with_rows([], pricing=pricing)
        assert await prov.estimate_vm_rightsizing_savings("Standard_D4s_v3", "eastus") == 0.0
