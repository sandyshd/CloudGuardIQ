"""Live pricing fetcher with 24-hour TTL cache for Azure, AWS, and GCP.

Architecture
------------
Prices are refreshed **at most once per 24 hours** (per process) from cloud
pricing APIs and kept in a module-level cache dict.  The policy engine calls
``get_fallback_cost()`` synchronously -- there are no network calls inside
rule evaluation.

``refresh_prices()`` should be awaited by the scan pipeline *before* running
a scan batch so the cache is warm.  On first use without a prior refresh the
static fallback values defined in ``_STATIC_FALLBACK`` are returned
immediately.

Graceful degradation
--------------------
Every cloud-specific fetcher wraps all exceptions.  On failure the cache
retains its previous values (or static defaults on first boot).  A warning
is logged but no exception propagates to the scan pipeline.

API sources
-----------
Azure : https://prices.azure.com/api/retail/prices  (no auth required)
AWS   : ``boto3`` ``pricing`` client (us-east-1, requires AWS credentials)
GCP   : ``google.cloud.billing`` ``CloudCatalogClient`` (requires Google
        Application Default Credentials)

When cloud credentials are absent the corresponding fetcher is skipped and
the static fallback value for that cloud is kept.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS: float = 86_400.0  # 24 hours

# ---------------------------------------------------------------------------
# Static fallback (conservative category medians, USD/month, May 2026).
# These are used until a successful live fetch overwrites them and whenever
# a live fetch fails.  See engine.py docstring for per-entry source refs.
# ---------------------------------------------------------------------------
_STATIC_FALLBACK: dict[str, float] = {
    # Azure
    "microsoft.compute/virtualmachines": 150.0,
    "microsoft.compute/disks": 45.0,
    "microsoft.compute/snapshots": 10.0,
    "microsoft.network/publicipaddresses": 3.65,
    "microsoft.network/loadbalancers": 18.0,
    "microsoft.network/applicationgateways": 60.0,
    "microsoft.network/networksecuritygroups": 0.0,
    "microsoft.keyvault/vaults": 5.0,
    "microsoft.storage/storageaccounts": 20.0,
    "microsoft.sql/servers": 150.0,
    "microsoft.sql/managedinstances": 500.0,
    "microsoft.documentdb/databaseaccounts": 25.0,
    "microsoft.containerservice/managedclusters": 120.0,
    "microsoft.web/sites": 10.0,
    "microsoft.cache/redis": 55.0,
    # AWS
    "aws::ec2::instance": 150.0,
    "aws::ec2::volume": 40.0,
    "aws::ec2::securitygroup": 0.0,
    "aws::rds::dbinstance": 200.0,
    "aws::rds::dbcluster": 300.0,
    "aws::s3::bucket": 25.0,
    "aws::lambda::function": 2.0,
    "aws::elasticloadbalancingv2::loadbalancer": 20.0,
    "aws::cloudtrail::trail": 5.0,
    "aws::iam::role": 0.0,
    "aws::iam::user": 0.0,
    # GCP
    "compute.googleapis.com/instance": 140.0,
    "compute.googleapis.com/disk": 40.0,
    "compute.googleapis.com/firewall": 0.0,
    "storage.googleapis.com/bucket": 23.0,
    "sqladmin.googleapis.com/instance": 180.0,
    "container.googleapis.com/cluster": 120.0,
    "cloudkms.googleapis.com/cryptokey": 6.0,
}

_HOURS_PER_MONTH: float = 730.0

# ---------------------------------------------------------------------------
# Azure Retail Prices API queries
# (public endpoint -- no authentication required)
#
# Each entry: (resource_type_key, OData filter, transform)
# transform values:
#   "hourly"        -- API returns USD/hr; multiply by _HOURS_PER_MONTH
#   "monthly"       -- API returns USD/month directly
#   "per_gb_128"    -- API returns USD/GB-month; multiply by 128 (representative)
# ---------------------------------------------------------------------------
_AZURE_QUERIES: list[tuple[str, str, str]] = [
    (
        "microsoft.compute/virtualmachines",
        (
            "armSkuName eq 'Standard_D4s_v5'"
            " and armRegionName eq 'eastus'"
            " and priceType eq 'Consumption'"
            " and contains(productName, 'Linux')"
        ),
        "hourly",
    ),
    (
        "microsoft.compute/disks",
        (
            "productName eq 'Standard SSD Managed Disks'"
            " and skuName eq 'E10 LRS'"
            " and armRegionName eq 'eastus'"
        ),
        "per_gb_128",
    ),
    (
        "microsoft.network/publicipaddresses",
        (
            "productName eq 'IP Addresses'"
            " and skuName eq 'Static Public IP'"
            " and armRegionName eq 'eastus'"
        ),
        "hourly",
    ),
    (
        "microsoft.storage/storageaccounts",
        (
            "productName eq 'Azure Blob Storage'"
            " and skuName eq 'Hot LRS'"
            " and armRegionName eq 'eastus'"
            " and meterName eq '1 TB/Month'"
        ),
        "monthly",
    ),
    (
        "microsoft.keyvault/vaults",
        (
            "productName eq 'Key Vault'"
            " and skuName eq 'Standard'"
            " and armRegionName eq 'eastus'"
            " and meterName eq 'Operations'"
        ),
        "monthly",
    ),
]

# ---------------------------------------------------------------------------
# AWS representative SKUs for the boto3 pricing client.
# Each entry: (resource_type_key, ServiceCode, filters, transform)
# ---------------------------------------------------------------------------
_AWS_QUERIES: list[tuple[str, str, list[dict[str, str]], str]] = [
    (
        "aws::ec2::instance",
        "AmazonEC2",
        [
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": "m5.xlarge"},
            {"Type": "TERM_MATCH", "Field": "location", "Value": "US East (N. Virginia)"},
            {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
            {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
            {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
            {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
        ],
        "hourly",
    ),
    (
        "aws::rds::dbinstance",
        "AmazonRDS",
        [
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": "db.m5.xlarge"},
            {"Type": "TERM_MATCH", "Field": "location", "Value": "US East (N. Virginia)"},
            {"Type": "TERM_MATCH", "Field": "databaseEngine", "Value": "MySQL"},
            {"Type": "TERM_MATCH", "Field": "deploymentOption", "Value": "Single-AZ"},
        ],
        "hourly",
    ),
    (
        "aws::elasticloadbalancingv2::loadbalancer",
        "AmazonEC2",
        [
            {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Load Balancer-Application"},
            {"Type": "TERM_MATCH", "Field": "location", "Value": "US East (N. Virginia)"},
            {"Type": "TERM_MATCH", "Field": "group", "Value": "Balancer:Application"},
        ],
        "hourly",
    ),
]


class _PricingCache:
    """Module-level singleton that holds live or static fallback prices."""

    def __init__(self) -> None:
        self._prices: dict[str, float] = dict(_STATIC_FALLBACK)
        self._fetched_at: float = 0.0
        self._lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def get(self, resource_type: str) -> float:
        """Return the cached fallback cost for *resource_type* (sync)."""
        key = resource_type.lower()
        for prefix, cost in self._prices.items():
            if key.startswith(prefix):
                return cost
        return 0.0

    def is_stale(self) -> bool:
        """Return True if the cache is older than the TTL or was never set."""
        return (time.monotonic() - self._fetched_at) > _CACHE_TTL_SECONDS

    async def refresh(self) -> None:
        """Re-fetch prices from all available cloud pricing APIs."""
        lock = self._get_lock()
        async with lock:
            if not self.is_stale():
                return
            new_prices: dict[str, float] = {}
            new_prices.update(await _fetch_azure_prices())
            new_prices.update(await _fetch_aws_prices())
            new_prices.update(await _fetch_gcp_prices())
            # Merge: live prices win; static fallback fills any gaps
            merged = {**_STATIC_FALLBACK, **new_prices}
            self._prices = merged
            self._fetched_at = time.monotonic()
            logger.info(
                "Pricing cache refreshed: %d entries (%d from live APIs)",
                len(merged),
                len(new_prices),
            )


_cache = _PricingCache()


def get_fallback_cost(resource_type: str) -> float:
    """Return the best available fallback monthly cost (USD) for a resource type.

    Reads from the module-level cache synchronously.  Returns ``0.0`` when
    the resource type is unrecognised.

    Call ``await refresh_prices()`` before a scan to keep prices current.
    """
    return _cache.get(resource_type)


async def refresh_prices() -> None:
    """Refresh the pricing cache from live APIs if the TTL has elapsed.

    Safe to call before every scan -- the TTL prevents unnecessary requests.
    Errors in individual cloud fetchers are logged as warnings and do not
    propagate.
    """
    await _cache.refresh()


# ---------------------------------------------------------------------------
# Per-cloud fetchers
# ---------------------------------------------------------------------------


async def _fetch_azure_prices() -> dict[str, float]:
    """Fetch representative on-demand prices from the Azure Retail Prices API.

    No authentication is required.  Queries a single well-known SKU per
    resource category so results are deterministic and fast.
    """
    url = "https://prices.azure.com/api/retail/prices"
    params_base = {"api-version": "2023-01-01-preview"}
    result: dict[str, float] = {}

    async with httpx.AsyncClient(timeout=10.0) as client:
        for resource_type, odata_filter, transform in _AZURE_QUERIES:
            try:
                resp = await client.get(
                    url,
                    params={**params_base, "$filter": odata_filter},
                )
                resp.raise_for_status()
                items = resp.json().get("Items", [])
                prices = [
                    float(item["retailPrice"])
                    for item in items
                    if item.get("retailPrice", 0) > 0
                ]
                if not prices:
                    continue
                price = prices[0]  # First match is the canonical SKU we filtered for
                if transform == "hourly":
                    result[resource_type] = round(price * _HOURS_PER_MONTH, 2)
                elif transform == "per_gb_128":
                    result[resource_type] = round(price * 128, 2)
                else:  # "monthly"
                    result[resource_type] = round(price, 2)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Azure pricing fetch failed for %s: %s", resource_type, exc
                )

    if result:
        logger.debug("Azure pricing: fetched %d entries", len(result))
    return result


async def _fetch_aws_prices() -> dict[str, float]:
    """Fetch on-demand prices from the AWS Pricing API via boto3.

    Requires valid AWS credentials in the environment (e.g. IAM role,
    environment variables, or ~/.aws/credentials).  Skipped silently
    when credentials or the boto3 package are unavailable.
    """
    try:
        import boto3  # noqa: PLC0415
        from botocore.exceptions import BotoCoreError, ClientError  # noqa: PLC0415
    except ImportError:
        logger.debug("boto3 not available; skipping AWS pricing fetch")
        return {}

    result: dict[str, float] = {}

    def _extract_on_demand_hourly(product_json: str) -> float | None:
        """Parse the first On-Demand USD/hr price from a pricing product JSON."""
        try:
            product: dict[str, Any] = json.loads(product_json)
            terms = product.get("terms", {}).get("OnDemand", {})
            for term in terms.values():
                for dim in term.get("priceDimensions", {}).values():
                    usd = dim.get("pricePerUnit", {}).get("USD", "")
                    if usd:
                        return float(usd)
        except (KeyError, ValueError, TypeError):
            pass
        return None

    try:
        client = boto3.client("pricing", region_name="us-east-1")
        loop = asyncio.get_event_loop()

        for resource_type, service_code, filters, transform in _AWS_QUERIES:
            try:
                response = await loop.run_in_executor(
                    None,
                    lambda sc=service_code, fl=filters: client.get_products(
                        ServiceCode=sc, Filters=fl, MaxResults=1
                    ),
                )
                price_list = response.get("PriceList", [])
                if not price_list:
                    continue
                hourly = _extract_on_demand_hourly(price_list[0])
                if hourly is None:
                    continue
                if transform == "hourly":
                    result[resource_type] = round(hourly * _HOURS_PER_MONTH, 2)
                else:
                    result[resource_type] = round(hourly, 2)
            except (BotoCoreError, ClientError) as exc:
                logger.warning(
                    "AWS pricing fetch failed for %s: %s", resource_type, exc
                )
    except (BotoCoreError, ClientError, Exception) as exc:  # noqa: BLE001
        logger.warning("AWS pricing client initialisation failed: %s", exc)

    if result:
        logger.debug("AWS pricing: fetched %d entries", len(result))
    return result


async def _fetch_gcp_prices() -> dict[str, float]:
    """Fetch on-demand prices from the GCP Cloud Billing Catalog API.

    Requires Google Application Default Credentials (ADC) and the
    ``google-cloud-billing`` package.  Skipped silently when either is
    absent.

    GCP Compute Engine service ID : 6F81-5844-456A
    GCP Cloud Storage service ID  : 95FF-2EF5-5EA1
    """
    try:
        from google.cloud import billing_v1  # noqa: PLC0415
    except ImportError:
        logger.debug(
            "google-cloud-billing not installed; skipping GCP pricing fetch"
        )
        return {}

    # SKU display-name fragments we recognise as representative prices.
    # Format: (resource_type_key, service_id, sku_name_fragment, unit)
    _gcp_sku_queries: list[tuple[str, str, str, str]] = [
        (
            "compute.googleapis.com/instance",
            "6F81-5844-456A",  # Compute Engine
            "N2 Instance Core",
            "hourly_per_core_x4",  # n2-standard-4 = 4 cores
        ),
        (
            "compute.googleapis.com/disk",
            "6F81-5844-456A",
            "SSD backed PD Capacity",
            "per_gb_100",
        ),
        (
            "storage.googleapis.com/bucket",
            "95FF-2EF5-5EA1",  # Cloud Storage
            "Standard Storage US",
            "per_gb_1024",
        ),
    ]

    result: dict[str, float] = {}
    loop = asyncio.get_event_loop()

    try:
        catalog_client = billing_v1.CloudCatalogClient()
    except Exception as exc:  # noqa: BLE001
        logger.warning("GCP billing client init failed: %s", exc)
        return {}

    for resource_type, service_id, sku_fragment, unit in _gcp_sku_queries:
        try:
            skus = await loop.run_in_executor(
                None,
                lambda sid=service_id: list(
                    catalog_client.list_skus(
                        parent=f"services/{sid}",
                    )
                ),
            )
            for sku in skus:
                if sku_fragment.lower() not in sku.description.lower():
                    continue
                # Extract the first USD tiered rate
                for tier in sku.pricing_info:
                    for expr in tier.pricing_expression.tiered_rates:
                        unit_price = expr.unit_price
                        if unit_price.currency_code != "USD":
                            continue
                        nanos = unit_price.nanos or 0
                        units = unit_price.units or 0
                        usd_per_unit = units + nanos / 1e9
                        if usd_per_unit <= 0:
                            continue
                        if unit == "hourly_per_core_x4":
                            result[resource_type] = round(
                                usd_per_unit * _HOURS_PER_MONTH * 4, 2
                            )
                        elif unit == "per_gb_100":
                            result[resource_type] = round(usd_per_unit * 100, 2)
                        elif unit == "per_gb_1024":
                            result[resource_type] = round(usd_per_unit * 1024, 2)
                        break
                    if resource_type in result:
                        break
                if resource_type in result:
                    break
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "GCP pricing fetch failed for %s: %s", resource_type, exc
            )

    if result:
        logger.debug("GCP pricing: fetched %d entries", len(result))
    return result
