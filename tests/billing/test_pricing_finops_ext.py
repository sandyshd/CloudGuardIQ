"""Tests for PricingService FinOps extensions (Prompt 1).

Covers the on-demand VM-size price fetch, the structural next-size-down
map, and the newly registered fixed-cost SKU queries -- all without
hitting the public Retail Prices API.
"""

from __future__ import annotations

from typing import Any

import pytest

from cloudguardiq.billing.pricing import (
    _QUERIES,
    PricingService,
    _PriceQuery,
    _build_filter,
)


class _FakeResp:
    def __init__(self, status: int, payload: dict[str, Any]) -> None:
        self.status = status
        self._payload = payload

    async def __aenter__(self) -> "_FakeResp":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def json(self) -> dict[str, Any]:
        return self._payload


class _FakeSession:
    def __init__(self, payload: dict[str, Any], status: int = 200) -> None:
        self.payload = payload
        self.status = status
        self.calls: list[dict[str, Any]] = []

    async def __aenter__(self) -> "_FakeSession":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    def get(self, url: str, params: dict[str, Any] | None = None, timeout: Any = None) -> _FakeResp:
        self.calls.append(params or {})
        return _FakeResp(self.status, self.payload)


class TestNextSizeDown:
    def test_known_size_maps_to_smaller(self) -> None:
        svc = PricingService()
        assert svc.next_size_down("Standard_D4s_v3") == "Standard_D2s_v3"

    def test_unknown_size_returns_none(self) -> None:
        svc = PricingService()
        assert svc.next_size_down("Standard_Totally_Made_Up") is None

    def test_smallest_size_has_no_smaller(self) -> None:
        svc = PricingService()
        # A family entry point should map to None (nothing smaller to suggest).
        assert svc.next_size_down("Standard_D2s_v3") is None


class TestNewFixedCostQueries:
    def test_registers_lb_natgw_appgw(self) -> None:
        skus = {q.sku for q in _QUERIES}
        assert "load_balancer_standard" in skus
        assert "nat_gateway" in skus
        assert "app_gateway_v2" in skus

    def test_filter_includes_arm_sku_name_when_set(self) -> None:
        q = _PriceQuery(
            sku="vm_Standard_D2s_v3",
            service_name="Virtual Machines",
            arm_sku_name="Standard_D2s_v3",
        )
        flt = _build_filter(q, "eastus")
        assert "armSkuName eq 'Standard_D2s_v3'" in flt
        assert "serviceName eq 'Virtual Machines'" in flt
        assert "armRegionName eq 'eastus'" in flt


@pytest.mark.asyncio
class TestVmSizePriceOnDemand:
    async def test_fetches_and_caches_monthly_price(self) -> None:
        # 0.20 USD/hr -> 0.20 * 730 = 146.0 USD/mo.
        payload = {"Items": [{"retailPrice": 0.20, "armSkuName": "Standard_D2s_v3"}]}
        session = _FakeSession(payload)
        svc = PricingService(session_factory=lambda: session)
        price = await svc.get_vm_size_price("Standard_D2s_v3", "eastus")
        assert price == pytest.approx(146.0)
        # Second call should hit the cache, not the API.
        again = await svc.get_vm_size_price("Standard_D2s_v3", "eastus")
        assert again == pytest.approx(146.0)
        assert len(session.calls) == 1

    async def test_excludes_spot_and_low_priority(self) -> None:
        session = _FakeSession({"Items": [{"retailPrice": 0.20}]})
        svc = PricingService(session_factory=lambda: session)
        await svc.get_vm_size_price("Standard_D2s_v3", "eastus")
        flt = session.calls[0]["$filter"]
        assert "Spot" in flt
        assert "Low Priority" in flt

    async def test_miss_returns_none(self) -> None:
        session = _FakeSession({"Items": []})
        svc = PricingService(session_factory=lambda: session)
        assert await svc.get_vm_size_price("Standard_D2s_v3", "eastus") is None

    async def test_api_error_returns_none(self) -> None:
        session = _FakeSession({"Items": []}, status=500)
        svc = PricingService(session_factory=lambda: session)
        assert await svc.get_vm_size_price("Standard_D2s_v3", "eastus") is None
