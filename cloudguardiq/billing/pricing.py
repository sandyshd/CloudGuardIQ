"""CloudGuardIQ -- Azure Retail Prices service.

Wraps Microsoft's public Retail Prices API
(``https://prices.azure.com/api/retail/prices``) so FinOps rules never
hardcode a dollar amount that drifts when Azure adjusts list prices.

Design
------
* **Async refresh, sync read.** Rules are sync (the policy engine
  evaluates rules in a tight loop), so the service preloads prices on
  startup and exposes a plain ``get_price()`` that hits an in-process
  dict. Misses fall back to a bundled default so a cold start or an API
  outage never produces a ``$0`` waste estimate.
* **Cosmos cache (24h TTL).** Refreshed prices are persisted to the
  shared ``system`` container under partition_key ``pricing_cache`` so
  every replica/restart starts with last-known-good values without
  re-hitting the public API.
* **No auth required.** The Retail Prices endpoint is anonymous, so the
  client only needs aiohttp.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import aiohttp
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Public, anonymous endpoint. Documented at:
# https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices
_RETAIL_PRICES_URL = "https://prices.azure.com/api/retail/prices"

# How long a cached price is considered fresh. Azure list prices change
# rarely (months, not days) so a 24h TTL is plenty and keeps load on the
# Retail Prices API negligible.
_CACHE_TTL_SECONDS = 24 * 60 * 60

# Hours in an average month, used to convert hourly meters to per-month.
_HOURS_PER_MONTH = 730.0

# Bundled fallback prices (USD/month, US East list price, captured 2026-04).
# Used only when the cache is cold AND the Retail Prices API is unreachable.
# Keep this list short -- only fields actually consumed by a rule today.
_FALLBACKS: dict[str, float] = {
    "public_ip_standard": 3.65,
}


# ---------------------------------------------------------------------------
# Query specs -- one per "thing the product needs to know the price of"
# ---------------------------------------------------------------------------
class _PriceQuery(BaseModel):
    """OData ``$filter`` template for a single SKU we care about."""

    sku: str
    service_name: str
    product_name: str | None = None
    meter_name: str | None = None
    sku_name: str | None = None
    arm_sku_name: str | None = None
    price_type: str = "Consumption"
    # ``true`` if the meter is hourly and must be multiplied by 730 to get
    # a monthly price. Public IP, App Gateway, NAT gateway are all hourly.
    is_hourly: bool = True
    # Substrings that must NOT appear in skuName / productName. Used to strip
    # Spot, Low Priority, and Windows variants from a VM-size price lookup so
    # the returned figure is the Linux on-demand list price.
    exclude_skuname_contains: list[str] = []
    exclude_productname_contains: list[str] = []


_QUERIES: list[_PriceQuery] = [
    # Standard Static Public IP, billed hourly. Meter name is exactly
    # "Standard Static IP" across all regions in the public catalog.
    _PriceQuery(
        sku="public_ip_standard",
        service_name="Virtual Network",
        meter_name="Standard Static IP",
        is_hourly=True,
    ),
    # Standard Load Balancer hourly base charge.
    _PriceQuery(
        sku="load_balancer_standard",
        service_name="Load Balancer",
        meter_name="Standard Included LB Rules and Outbound Rules",
        is_hourly=True,
    ),
    # NAT Gateway hourly base charge.
    _PriceQuery(
        sku="nat_gateway",
        service_name="NAT Gateway",
        meter_name="Gateway",
        is_hourly=True,
    ),
    # Application Gateway v2 (Standard_v2) fixed hourly gateway charge.
    _PriceQuery(
        sku="app_gateway_v2",
        service_name="Application Gateway",
        meter_name="Standard v2 Gateway",
        is_hourly=True,
    ),
]


# Structural "next size down" map within a VM family. These are SKU *names*
# (cloud topology metadata), NOT prices -- the dollar values are always
# resolved live from the Retail Prices API. Used by the rightsizing
# estimator to price the recommended smaller SKU. Family entry points are
# intentionally absent so ``next_size_down`` returns ``None`` for them.
_VM_NEXT_SIZE_DOWN: dict[str, str] = {
    # Dsv3 general purpose
    "Standard_D4s_v3": "Standard_D2s_v3",
    "Standard_D8s_v3": "Standard_D4s_v3",
    "Standard_D16s_v3": "Standard_D8s_v3",
    "Standard_D32s_v3": "Standard_D16s_v3",
    "Standard_D64s_v3": "Standard_D32s_v3",
    # Dsv4 general purpose
    "Standard_D4s_v4": "Standard_D2s_v4",
    "Standard_D8s_v4": "Standard_D4s_v4",
    "Standard_D16s_v4": "Standard_D8s_v4",
    "Standard_D32s_v4": "Standard_D16s_v4",
    # Dsv5 general purpose
    "Standard_D4s_v5": "Standard_D2s_v5",
    "Standard_D8s_v5": "Standard_D4s_v5",
    "Standard_D16s_v5": "Standard_D8s_v5",
    "Standard_D32s_v5": "Standard_D16s_v5",
    # Esv3 memory optimised
    "Standard_E4s_v3": "Standard_E2s_v3",
    "Standard_E8s_v3": "Standard_E4s_v3",
    "Standard_E16s_v3": "Standard_E8s_v3",
    "Standard_E32s_v3": "Standard_E16s_v3",
    # Fsv2 compute optimised
    "Standard_F4s_v2": "Standard_F2s_v2",
    "Standard_F8s_v2": "Standard_F4s_v2",
    "Standard_F16s_v2": "Standard_F8s_v2",
    "Standard_F32s_v2": "Standard_F16s_v2",
}


def _build_filter(q: _PriceQuery, region: str) -> str:
    """Compose an OData ``$filter`` for a single (query, region) pair."""
    parts: list[str] = [
        f"serviceName eq '{q.service_name}'",
        f"armRegionName eq '{region}'",
        f"priceType eq '{q.price_type}'",
    ]
    if q.product_name:
        parts.append(f"productName eq '{q.product_name}'")
    if q.meter_name:
        parts.append(f"meterName eq '{q.meter_name}'")
    if q.sku_name:
        parts.append(f"skuName eq '{q.sku_name}'")
    if q.arm_sku_name:
        parts.append(f"armSkuName eq '{q.arm_sku_name}'")
    for token in q.exclude_skuname_contains:
        parts.append(f"contains(skuName, '{token}') eq false")
    for token in q.exclude_productname_contains:
        parts.append(f"contains(productName, '{token}') eq false")
    return " and ".join(parts)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------
class PricingService:
    """In-process price cache backed by Azure Retail Prices + Cosmos.

    Thread-safety: the service is designed to be a process-wide singleton.
    Reads are plain dict lookups (atomic in CPython); writes happen only
    inside :meth:`refresh` which runs on the event loop.
    """

    def __init__(
        self,
        *,
        regions: list[str] | None = None,
        repo: Any | None = None,
        session_factory: Any | None = None,
    ) -> None:
        self._regions = regions or [
            "eastus", "eastus2", "westus", "westus2", "westus3",
            "centralus", "northeurope", "westeurope",
            "uksouth", "southeastasia", "australiaeast",
        ]
        self._repo = repo
        # Allow tests to inject a fake aiohttp.ClientSession factory.
        self._session_factory = session_factory or aiohttp.ClientSession
        # Cache key is (sku, region_lower) -> USD/month.
        self._cache: dict[tuple[str, str], float] = {}
        self._last_refresh_ts: float = 0.0
        self._refresh_lock = asyncio.Lock()

    # -- public API ---------------------------------------------------------

    def get_price(self, sku: str, region: str, *, default: float | None = None) -> float:
        """Return the cached USD/month price for *sku* in *region*.

        Lookup is case-insensitive on region. Returns ``default`` when
        provided, otherwise the bundled fallback, otherwise ``0.0`` so a
        missing SKU never crashes a rule evaluation.
        """
        key = (sku, (region or "").lower())
        cached = self._cache.get(key)
        if cached is not None and cached > 0:
            return cached
        if default is not None:
            return default
        return _FALLBACKS.get(sku, 0.0)

    def is_stale(self) -> bool:
        """Return True if the cache was refreshed more than the TTL ago."""
        return (time.time() - self._last_refresh_ts) > _CACHE_TTL_SECONDS

    def next_size_down(self, vm_size: str) -> str | None:
        """Return the recommended smaller VM SKU within the same family.

        Returns ``None`` when no smaller SKU is registered (e.g. the size is
        already a family entry point or is unknown). The value is a SKU
        *name* only -- pricing is resolved live via :meth:`get_vm_size_price`.
        """
        return _VM_NEXT_SIZE_DOWN.get(vm_size)

    async def get_vm_size_price(self, vm_size: str, region: str) -> float | None:
        """Return the Linux on-demand list price (USD/month) for a VM size.

        Queries the Azure Retail Prices API on demand (VM SKUs are too
        numerous to preload) and caches the result by ``("vm_<size>",
        region)``. Spot, Low Priority, and Windows variants are excluded so
        the figure is the pay-as-you-go Linux list price. Returns ``None``
        on a miss or any error so callers can degrade gracefully.
        """
        key = (f"vm_{vm_size}", (region or "").lower())
        cached = self._cache.get(key)
        if cached is not None and cached > 0:
            return cached
        query = _PriceQuery(
            sku=key[0],
            service_name="Virtual Machines",
            arm_sku_name=vm_size,
            is_hourly=True,
            exclude_skuname_contains=["Spot", "Low Priority"],
            exclude_productname_contains=["Windows"],
        )
        try:
            async with self._session_factory() as session:
                price = await self._fetch_one(session, query, region)
        except Exception as exc:  # noqa: BLE001 -- pricing must never crash a scan
            logger.warning(
                "VM size price fetch failed for %s/%s: %s", vm_size, region, exc
            )
            return None
        if price is not None and price > 0:
            self._cache[key] = price
            return price
        return None

    async def warmup(self) -> None:
        """Hydrate from the Cosmos cache (best-effort, never raises).

        Called once on application startup before any scan is served so
        the very first scan after a cold start already has live prices.
        """
        if self._repo is None:
            return
        try:
            docs = await self._repo.load_pricing_cache()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Pricing cache warmup failed: %s", exc)
            return
        latest_ts = 0.0
        for doc in docs:
            sku = doc.get("sku")
            region = doc.get("region")
            price = doc.get("price_usd_monthly")
            ts = doc.get("refreshed_ts", 0)
            if not sku or not region or not isinstance(price, (int, float)):
                continue
            self._cache[(str(sku), str(region).lower())] = float(price)
            if isinstance(ts, (int, float)) and ts > latest_ts:
                latest_ts = float(ts)
        self._last_refresh_ts = latest_ts
        logger.info(
            "Pricing cache warmed: %d entries, age=%.0fs",
            len(self._cache),
            max(0.0, time.time() - latest_ts) if latest_ts else -1,
        )

    async def refresh(self) -> None:
        """Re-fetch every (SKU, region) pair from Azure Retail Prices.

        Best-effort: any HTTP error is logged and the existing cache is
        preserved -- under no circumstances does a metering failure
        clear a previously valid price.
        """
        async with self._refresh_lock:
            new_entries = 0
            try:
                async with self._session_factory() as session:
                    for q in _QUERIES:
                        for region in self._regions:
                            price = await self._fetch_one(session, q, region)
                            if price is None:
                                continue
                            self._cache[(q.sku, region.lower())] = price
                            new_entries += 1
                            if self._repo is not None:
                                try:
                                    await self._repo.save_pricing_cache(
                                        sku=q.sku,
                                        region=region.lower(),
                                        price_usd_monthly=price,
                                    )
                                except Exception as exc:  # noqa: BLE001
                                    logger.warning(
                                        "Pricing cache save failed for %s/%s: %s",
                                        q.sku, region, exc,
                                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Retail Prices refresh failed: %s", exc)
                return
            self._last_refresh_ts = time.time()
            logger.info("Pricing cache refreshed: %d entries updated", new_entries)

    # -- internals ----------------------------------------------------------

    async def _fetch_one(
        self,
        session: aiohttp.ClientSession,
        q: _PriceQuery,
        region: str,
    ) -> float | None:
        """Return USD/month for a single (query, region) or ``None`` on miss."""
        params = {"$filter": _build_filter(q, region), "currencyCode": "USD"}
        try:
            async with session.get(
                _RETAIL_PRICES_URL,
                params=params,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    logger.warning(
                        "Retail Prices %s for %s/%s -> HTTP %d",
                        q.sku, q.service_name, region, resp.status,
                    )
                    return None
                payload = await resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Retail Prices request failed for %s/%s: %s",
                q.sku, region, exc,
            )
            return None
        items = payload.get("Items") or []
        if not items:
            return None
        # Multiple SKUs can match (e.g. Standard vs Basic IP). The smallest
        # price is the conservative choice for "list price of the cheapest
        # variant the user could be billed at".
        retail_prices = [
            float(it["retailPrice"]) for it in items if "retailPrice" in it
        ]
        if not retail_prices:
            return None
        unit_price = min(retail_prices)
        if q.is_hourly:
            return round(unit_price * _HOURS_PER_MONTH, 2)
        return round(unit_price, 2)


# ---------------------------------------------------------------------------
# Module-level singleton -- rules import this and call .get_price()
# ---------------------------------------------------------------------------
_service: PricingService = PricingService()


def get_pricing_service() -> PricingService:
    """Return the process-wide :class:`PricingService` singleton."""
    return _service


def configure_pricing_service(service: PricingService) -> None:
    """Replace the singleton (used by lifespan startup and tests)."""
    global _service  # noqa: PLW0603
    _service = service
