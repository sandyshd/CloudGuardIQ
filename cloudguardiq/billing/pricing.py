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
    price_type: str = "Consumption"
    # ``true`` if the meter is hourly and must be multiplied by 730 to get
    # a monthly price. Public IP, App Gateway, NAT gateway are all hourly.
    is_hourly: bool = True


_QUERIES: list[_PriceQuery] = [
    # Standard Static Public IP, billed hourly. Meter name is exactly
    # "Standard Static IP" across all regions in the public catalog.
    _PriceQuery(
        sku="public_ip_standard",
        service_name="Virtual Network",
        meter_name="Standard Static IP",
        is_hourly=True,
    ),
]


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
