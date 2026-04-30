"""Tests for the Azure Retail Prices service."""

from __future__ import annotations

from typing import Any

import pytest

from cloudguardiq.billing.pricing import (
    PricingService,
    _build_filter,
    _PriceQuery,
)


class _FakeResp:
    def __init__(self, status: int, payload: dict[str, Any]) -> None:
        self.status = status
        self._payload = payload

    async def __aenter__(self) -> _FakeResp:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def json(self) -> dict[str, Any]:
        return self._payload


class _FakeSession:
    def __init__(self, payloads: dict[str, dict[str, Any]] | None = None,
                 status: int = 200) -> None:
        self.payloads = payloads or {}
        self.status = status
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    def get(self, url: str, params: dict[str, Any] | None = None,
            timeout: Any = None) -> _FakeResp:
        self.calls.append((url, params or {}))
        # match by region in $filter
        flt = (params or {}).get("$filter", "")
        for region, payload in self.payloads.items():
            if f"armRegionName eq '{region}'" in flt:
                return _FakeResp(self.status, payload)
        return _FakeResp(self.status, {"Items": []})


class _FakeRepo:
    def __init__(self) -> None:
        self.saved: list[dict[str, Any]] = []
        self.preload: list[dict[str, Any]] = []

    async def save_pricing_cache(self, *, sku: str, region: str,
                                 price_usd_monthly: float) -> None:
        self.saved.append({
            "sku": sku, "region": region,
            "price_usd_monthly": price_usd_monthly,
        })

    async def load_pricing_cache(self) -> list[dict[str, Any]]:
        return list(self.preload)


def _payload_with_price(hourly: float) -> dict[str, Any]:
    return {"Items": [{"retailPrice": hourly}]}


def test_build_filter_includes_required_clauses() -> None:
    q = _PriceQuery(sku="x", service_name="Virtual Network",
                    meter_name="Standard Static IP")
    flt = _build_filter(q, "eastus")
    assert "serviceName eq 'Virtual Network'" in flt
    assert "armRegionName eq 'eastus'" in flt
    assert "meterName eq 'Standard Static IP'" in flt
    assert "priceType eq 'Consumption'" in flt


@pytest.mark.asyncio
async def test_refresh_populates_cache_and_persists() -> None:
    repo = _FakeRepo()
    session = _FakeSession(payloads={
        "eastus": _payload_with_price(0.005),
        "westeurope": _payload_with_price(0.006),
    })
    svc = PricingService(
        regions=["eastus", "westeurope"],
        repo=repo,
        session_factory=lambda: session,
    )
    await svc.refresh()
    # 0.005/hr * 730 hr = 3.65
    assert svc.get_price("public_ip_standard", "eastus") == 3.65
    assert svc.get_price("public_ip_standard", "westeurope") == 4.38
    # Cosmos persistence
    saved_skus = {(d["sku"], d["region"]) for d in repo.saved}
    assert ("public_ip_standard", "eastus") in saved_skus
    assert ("public_ip_standard", "westeurope") in saved_skus


@pytest.mark.asyncio
async def test_refresh_failure_keeps_existing_cache() -> None:
    svc = PricingService(regions=["eastus"], repo=None,
                         session_factory=lambda: _FakeSession(status=500))
    svc._cache[("public_ip_standard", "eastus")] = 9.99
    await svc.refresh()
    # Existing entry preserved
    assert svc.get_price("public_ip_standard", "eastus") == 9.99


def test_get_price_falls_back_to_bundled_default_on_miss() -> None:
    svc = PricingService(regions=[], repo=None)
    # Cold cache + no override -> bundled fallback
    assert svc.get_price("public_ip_standard", "eastus") == 3.65
    # Unknown SKU + explicit default -> default wins
    assert svc.get_price("unknown_sku", "eastus", default=1.23) == 1.23
    # Unknown SKU, no default -> 0.0 (never crashes)
    assert svc.get_price("unknown_sku", "eastus") == 0.0


@pytest.mark.asyncio
async def test_warmup_loads_from_repo() -> None:
    repo = _FakeRepo()
    repo.preload = [
        {"sku": "public_ip_standard", "region": "eastus",
         "price_usd_monthly": 4.20, "refreshed_ts": 1_700_000_000},
    ]
    svc = PricingService(regions=["eastus"], repo=repo)
    await svc.warmup()
    assert svc.get_price("public_ip_standard", "EastUS") == 4.20  # case-insensitive
