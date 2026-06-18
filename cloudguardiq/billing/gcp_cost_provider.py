"""CloudGuardIQ -- GCP cost provider.

Concrete :class:`~cloudguardiq.billing.cost_provider.CostProvider` for Google
Cloud. It is the single seam that talks to the Cloud Billing BigQuery export
(actual billed cost) and the Cloud Billing Catalog API (list price), with the
static :mod:`cloudguardiq.adapters.pricing.catalog` retained only as the
offline fallback of last resort inside list-price lookups.

Design notes
------------
* **Actual cost**: GCP has no per-resource cost REST API. The standard
  mechanism is the Cloud Billing -> BigQuery export. We ``SUM(cost)`` grouped
  by ``resource.name`` over the Prompt-0 billing window (default: last full
  calendar month). The fully-qualified export table id comes from
  configuration (``GCG_GCP_BILLING_EXPORT_TABLE`` / constructor) -- never
  hardcoded. When the table is absent or the query fails (not set up, IAM
  denied), we log a warning and return ``{}`` so callers fall back to list
  price. Cost is never a hard dependency.
* **List price**: the Cloud Billing Catalog API (``CloudCatalogClient``:
  ``list_services`` -> ``list_skus``) resolves live SKU pricing. We parse
  ``pricing_info -> pricing_expression -> tiered_rates -> unit_price``
  (``units`` + ``nanos``) into USD. Capacity SKUs (GiB-month) multiply by the
  provisioned size; compute SKUs (hourly) convert at 730 h/month. Results are
  cached in-process by ``(sku, region)``.
* **Rightsizing**: GCE savings are the live price delta between the current
  machine type and the recommended one-size-down type -- never a flat fraction.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from cloudguardiq.adapters.pricing.catalog import gcp_persistent_disk_monthly_usd
from cloudguardiq.billing.cost_provider import HOURS_PER_MONTH, CostProvider, CostWindow
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import FocusCostRecord

logger = logging.getLogger(__name__)

# Environment variable holding the fully-qualified BigQuery billing export
# table id (``project.dataset.gcp_billing_export_v1_XXXXXX``).
_BILLING_EXPORT_TABLE_ENV = "GCG_GCP_BILLING_EXPORT_TABLE"

# Catalog service whose SKUs cover Compute Engine disks, machine types,
# external IPs, and load balancing.
_COMPUTE_ENGINE_SERVICE = "Compute Engine"

# Disk type -> Catalog SKU description fragment (capacity, GiB-month). These
# are description *matchers* (topology metadata), not prices.
_PD_DESCRIPTION: dict[str, str] = {
    "pd-standard": "Storage PD Capacity",
    "pd-balanced": "Balanced PD Capacity",
    "pd-ssd": "SSD backed PD Capacity",
    "pd-extreme": "Extreme PD Capacity",
    "hyperdisk-balanced": "Hyperdisk Balanced Capacity",
}

# Structural "next size down" map within a GCE machine family. Instance *type*
# names only -- dollar values are always resolved live from the Catalog API.
# Family entry points (e.g. ``*-standard-1`` / shared-core) are intentionally
# absent so ``next_machine_size_down`` returns ``None`` for them.
_GCE_NEXT_SIZE_DOWN: dict[str, str] = {
    # n1 standard
    "n1-standard-96": "n1-standard-64",
    "n1-standard-64": "n1-standard-32",
    "n1-standard-32": "n1-standard-16",
    "n1-standard-16": "n1-standard-8",
    "n1-standard-8": "n1-standard-4",
    "n1-standard-4": "n1-standard-2",
    "n1-standard-2": "n1-standard-1",
    # n2 standard
    "n2-standard-80": "n2-standard-48",
    "n2-standard-48": "n2-standard-32",
    "n2-standard-32": "n2-standard-16",
    "n2-standard-16": "n2-standard-8",
    "n2-standard-8": "n2-standard-4",
    "n2-standard-4": "n2-standard-2",
    # e2 standard
    "e2-standard-32": "e2-standard-16",
    "e2-standard-16": "e2-standard-8",
    "e2-standard-8": "e2-standard-4",
    "e2-standard-4": "e2-standard-2",
    # c2 compute optimised
    "c2-standard-60": "c2-standard-30",
    "c2-standard-30": "c2-standard-16",
    "c2-standard-16": "c2-standard-8",
    "c2-standard-8": "c2-standard-4",
}


class GcpCostProvider(CostProvider):
    """GCP implementation of the :class:`CostProvider` contract."""

    actual_cost_tier: DataTier = DataTier.TIER2_ENRICHED
    list_price_tier: DataTier = DataTier.TIER1_NATIVE

    def __init__(
        self,
        project_id: str,
        *,
        billing_export_table: str | None = None,
        credentials: Any | None = None,
        catalog_client: Any | None = None,
        bigquery_client: Any | None = None,
    ) -> None:
        """Initialise the provider.

        Args:
            project_id: GCP project id (scoping/logging).
            billing_export_table: Fully-qualified BigQuery export table id.
                Falls back to ``GCG_GCP_BILLING_EXPORT_TABLE``; when neither is
                set, actual-cost lookups short-circuit to ``{}``.
            credentials: Optional google credentials reused from the adapter.
            catalog_client: Injectable ``CloudCatalogClient`` (tests).
            bigquery_client: Injectable ``bigquery.Client`` (tests).
        """
        self.project_id = project_id
        self._billing_export_table = billing_export_table or os.environ.get(
            _BILLING_EXPORT_TABLE_ENV,
        )
        self._credentials = credentials
        self._catalog_client = catalog_client
        self._bigquery_client = bigquery_client
        # (sku, region) -> monthly USD (or per-GiB for the pd_gib:* keys).
        self._cache: dict[tuple[str, str], float] = {}

    # -- client helpers -----------------------------------------------------

    def _get_catalog(self) -> Any:
        if self._catalog_client is None:
            from google.cloud import billing_v1

            self._catalog_client = billing_v1.CloudCatalogClient(
                credentials=self._credentials,
            )
        return self._catalog_client

    def _get_bigquery(self) -> Any:
        if self._bigquery_client is None:
            from google.cloud import bigquery

            self._bigquery_client = bigquery.Client(
                project=self.project_id, credentials=self._credentials,
            )
        return self._bigquery_client

    # -- actual cost --------------------------------------------------------

    async def _fetch_actual_cost(
        self, resource_ids: list[str], window: CostWindow
    ) -> dict[str, float]:
        """Query the BigQuery billing export for monthly cost per resource."""
        if not self._billing_export_table:
            logger.info(
                "No GCP billing export table configured (%s) -- skipping "
                "actual-cost lookup",
                _BILLING_EXPORT_TABLE_ENV,
            )
            return {}

        loop = asyncio.get_running_loop()
        start = window.start.strftime("%Y-%m-%d")
        end = window.end.strftime("%Y-%m-%d")
        # Parameterless interpolation is safe here: the table id is operator
        # configuration (not user input) and the dates are derived internally.
        sql = (
            "SELECT resource.name AS resource_name, "
            "SUM(cost) AS cost "
            f"FROM `{self._billing_export_table}` "
            "WHERE resource.name IS NOT NULL "
            f"AND usage_start_time >= TIMESTAMP('{start}') "
            f"AND usage_start_time <= TIMESTAMP('{end} 23:59:59') "
            "GROUP BY resource_name"
        )

        def _run() -> dict[str, float]:
            client = self._get_bigquery()
            job = client.query(sql)
            out: dict[str, float] = {}
            for row in job.result():
                name = row["resource_name"]
                if not name:
                    continue
                out[str(name).lower()] = out.get(str(name).lower(), 0.0) + float(
                    row["cost"] or 0.0
                )
            return out

        cost_map = await loop.run_in_executor(None, _run)
        logger.info("Fetched GCP cost data for %d resources", len(cost_map))
        return cost_map

    # -- FOCUS cost and usage ----------------------------------------------

    async def _fetch_cost_and_usage(
        self, window: CostWindow
    ) -> list[FocusCostRecord]:
        """Query the BigQuery billing export and map rows to FOCUS records.

        Aggregates ``SUM(cost)`` and ``SUM(usage.amount)`` grouped by service,
        SKU, project, region and resource name over the billing window. The
        fully-qualified export table id is operator configuration (never
        hardcoded); when unset the lookup short-circuits to ``[]``.
        """
        if not self._billing_export_table:
            logger.info(
                "No GCP billing export table configured (%s) -- skipping "
                "cost-and-usage lookup",
                _BILLING_EXPORT_TABLE_ENV,
            )
            return []

        loop = asyncio.get_running_loop()
        start = window.start.strftime("%Y-%m-%d")
        end = window.end.strftime("%Y-%m-%d")
        # Table id is operator config (not user input); dates are internal.
        sql = (
            "SELECT service.description AS service_name, "
            "sku.id AS sku_id, "
            "project.id AS project_id, "
            "location.region AS region, "
            "resource.name AS resource_name, "
            "ANY_VALUE(currency) AS currency, "
            "ANY_VALUE(billing_account_id) AS billing_account_id, "
            "SUM(cost) AS cost, "
            "SUM(usage.amount) AS usage_amount, "
            "ANY_VALUE(usage.unit) AS usage_unit "
            f"FROM `{self._billing_export_table}` "
            f"WHERE usage_start_time >= TIMESTAMP('{start}') "
            f"AND usage_start_time <= TIMESTAMP('{end} 23:59:59') "
            "GROUP BY service_name, sku_id, project_id, region, resource_name"
        )

        def _run() -> list[FocusCostRecord]:
            client = self._get_bigquery()
            job = client.query(sql)
            return self._rows_to_focus(job.result(), window)

        records = await loop.run_in_executor(None, _run)
        logger.info("Mapped %d GCP FOCUS cost records", len(records))
        return records

    def _rows_to_focus(
        self, rows: Any, window: CostWindow
    ) -> list[FocusCostRecord]:
        """Map BigQuery billing export rows into FOCUS records."""
        period = window.start.strftime("%Y-%m")

        def _get(row: Any, key: str, default: Any = "") -> Any:
            try:
                value = row[key]
            except (KeyError, TypeError, IndexError):
                return default
            return value if value is not None else default

        records: list[FocusCostRecord] = []
        for row in rows:
            cost = float(_get(row, "cost", 0.0) or 0.0)
            project_id = str(_get(row, "project_id", "") or "")
            records.append(
                FocusCostRecord(
                    billing_period=period,
                    charge_period_start=window.start,
                    charge_period_end=window.end,
                    billed_cost=cost,
                    effective_cost=cost,
                    list_cost=cost,
                    billing_currency=str(_get(row, "currency", "USD") or "USD"),
                    provider=CloudProvider.GCP,
                    billing_account_id=str(_get(row, "billing_account_id", "") or ""),
                    sub_account_id=project_id,
                    service_name=str(_get(row, "service_name", "") or ""),
                    sku_id=str(_get(row, "sku_id", "") or ""),
                    resource_id=str(_get(row, "resource_name", "") or "").lower(),
                    region=str(_get(row, "region", "") or ""),
                    usage_quantity=float(_get(row, "usage_amount", 0.0) or 0.0),
                    usage_unit=str(_get(row, "usage_unit", "") or ""),
                    data_tier=self.actual_cost_tier,
                )
            )
        return records

    # -- list price ---------------------------------------------------------

    async def _fetch_list_price(self, sku: str, region: str) -> float | None:
        """Resolve a logical GCP *sku* to a monthly USD list price.

        Supported sku encodings:
          * ``pd:<disk_type>:<size_gb>`` -> per-GiB-month price x size.
          * ``gce:<machine_type>``       -> hourly on-demand x 730.

        Falls back to the static catalog (logged) when the Catalog API misses;
        returns ``None`` when no price is obtainable.
        """
        parts = sku.split(":")
        kind = parts[0]

        if kind == "pd":
            disk_type = parts[1] if len(parts) > 1 else ""
            size_gb = float(parts[2]) if len(parts) > 2 and parts[2] else 0.0
            per_gib = await self._pd_per_gib_month(disk_type, region)
            if per_gib is not None and size_gb:
                return round(per_gib * size_gb, 2)
            fallback = gcp_persistent_disk_monthly_usd(disk_type, size_gb)
            if fallback > 0:
                logger.warning(
                    "PD list price: using static catalog fallback for %s/%s",
                    disk_type, region,
                )
                return fallback
            return None

        if kind == "gce":
            machine_type = parts[1] if len(parts) > 1 else ""
            return await self._gce_machine_monthly(machine_type, region)

        return None

    # -- Catalog parsing helpers -------------------------------------------

    async def _resolve_catalog_unit_price(
        self, description_contains: str, region: str
    ) -> float | None:
        """Return the unit price (USD) of the matching Compute Engine SKU.

        Matches by region membership and a case-insensitive description
        substring. Degrades to ``None`` on any Catalog API error so a pricing
        outage can never break a scan.
        """
        loop = asyncio.get_running_loop()
        needle = description_contains.lower()
        target_region = region.lower()

        def _lookup() -> float | None:
            client = self._get_catalog()
            for service in client.list_services():
                if _COMPUTE_ENGINE_SERVICE.lower() not in (
                    getattr(service, "display_name", "") or ""
                ).lower():
                    continue
                for item in client.list_skus(parent=service.name):
                    description = (getattr(item, "description", "") or "").lower()
                    if needle not in description:
                        continue
                    regions = [
                        str(r).lower() for r in (getattr(item, "service_regions", []) or [])
                    ]
                    if target_region not in regions and "global" not in regions:
                        continue
                    price = _parse_sku_unit_price(item)
                    if price is not None and price > 0:
                        return price
            return None

        try:
            return await loop.run_in_executor(None, _lookup)
        except Exception as exc:  # noqa: BLE001 -- pricing must never crash a scan
            logger.warning(
                "Catalog lookup failed for %r/%s: %s", description_contains, region, exc,
            )
            return None

    async def _pd_per_gib_month(self, disk_type: str, region: str) -> float | None:
        """Live per-GiB-month price for a persistent disk type, cached."""
        key = (f"pd_gib:{disk_type}", region.lower())
        cached = self._cache.get(key)
        if cached is not None and cached > 0:
            return cached
        description = _PD_DESCRIPTION.get(disk_type)
        if not description:
            return None
        price = await self._resolve_catalog_unit_price(description, region)
        if price is not None and price > 0:
            self._cache[key] = price
            return price
        return None

    async def _gce_machine_monthly(self, machine_type: str, region: str) -> float | None:
        """Live monthly price for a GCE machine type, cached."""
        if not machine_type:
            return None
        key = (f"gce:{machine_type}", region.lower())
        cached = self._cache.get(key)
        if cached is not None and cached > 0:
            return cached
        hourly = await self._resolve_catalog_unit_price(machine_type, region)
        if hourly is None or hourly <= 0:
            return None
        monthly = round(hourly * HOURS_PER_MONTH, 2)
        self._cache[key] = monthly
        return monthly

    # -- rightsizing --------------------------------------------------------

    def next_machine_size_down(self, machine_type: str) -> str | None:
        """Return the recommended smaller machine type, or ``None``."""
        return _GCE_NEXT_SIZE_DOWN.get(machine_type)

    async def estimate_gce_rightsizing_savings(
        self, machine_type: str, region: str
    ) -> float:
        """Estimate monthly savings from resizing a GCE VM one machine down.

        Computes ``current_price - recommended_smaller_price`` using live
        Catalog data. Returns ``0.0`` when the type is unknown, has no smaller
        type, or either price is unavailable -- never negative.
        """
        smaller = self.next_machine_size_down(machine_type)
        if not smaller:
            return 0.0
        current = await self._gce_machine_monthly(machine_type, region)
        recommended = await self._gce_machine_monthly(smaller, region)
        if current is None or recommended is None:
            return 0.0
        return round(max(0.0, current - recommended), 2)


def _parse_sku_unit_price(sku: Any) -> float | None:
    """Parse the first positive tiered unit price (USD) from a Catalog SKU.

    Reads ``pricing_info[].pricing_expression.tiered_rates[].unit_price`` and
    converts the ``units`` + ``nanos`` money fields to a float USD amount.
    """
    for pricing_info in getattr(sku, "pricing_info", []) or []:
        expression = getattr(pricing_info, "pricing_expression", None)
        if expression is None:
            continue
        for tier in getattr(expression, "tiered_rates", []) or []:
            unit_price = getattr(tier, "unit_price", None)
            if unit_price is None:
                continue
            units = float(getattr(unit_price, "units", 0) or 0)
            nanos = float(getattr(unit_price, "nanos", 0) or 0)
            value = units + nanos / 1_000_000_000.0
            if value > 0:
                return value
    return None
