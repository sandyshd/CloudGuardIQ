"""CloudGuardIQ -- AWS cost provider.

Concrete :class:`~cloudguardiq.billing.cost_provider.CostProvider` for AWS.
It is the single seam that talks to AWS Cost Explorer (actual billed cost)
and the AWS Price List Query API (list price), with the static
:mod:`cloudguardiq.adapters.pricing.catalog` retained only as the offline
fallback of last resort inside list-price lookups.

Design notes
------------
* **Actual cost** uses ``ce.get_cost_and_usage`` with the ``AmortizedCost``
  metric (RI/Savings-Plan aware, aligning with the FOCUS ``EffectiveCost``
  semantic) grouped by ``RESOURCE_ID`` over the Prompt-0 billing window
  (default: last full calendar month). Resource-level granularity must be
  enabled on the payer account; when no resource rows come back, callers
  fall back to list price. Any failure (IAM denial, throttling) degrades to
  ``{}`` -- Cost Explorer is never a hard dependency.
* **List price** uses the Price List Query API (``pricing`` client, only
  available in ``us-east-1``/``ap-south-1`` -- pinned to ``us-east-1``) but
  queries the price *for the resource's actual region* via the
  ``regionCode`` attribute filter. Hourly meters are converted to monthly at
  730 h/month. Results are cached in-process by ``(sku, region)``.
* **Rightsizing** estimates EC2 savings as the live price delta between the
  current instance type and the recommended one-size-down type -- never a
  flat percentage.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import timedelta
from typing import Any

from cloudguardiq.adapters.pricing.catalog import (
    aws_ebs_monthly_usd,
    aws_eip_unattached_monthly_usd,
)
from cloudguardiq.billing.cost_provider import HOURS_PER_MONTH, CostProvider, CostWindow
from cloudguardiq.core.enums import DataTier

logger = logging.getLogger(__name__)


# Structural "next size down" map within an EC2 family. These are instance
# *type* names (cloud topology metadata), NOT prices -- the dollar values are
# always resolved live from the Price List API. Family entry points (e.g.
# ``*.nano`` / ``*.micro``) are intentionally absent so ``next_instance_size_down``
# returns ``None`` for them.
_EC2_NEXT_SIZE_DOWN: dict[str, str] = {
    # t3 burstable
    "t3.2xlarge": "t3.xlarge",
    "t3.xlarge": "t3.large",
    "t3.large": "t3.medium",
    "t3.medium": "t3.small",
    "t3.small": "t3.micro",
    "t3.micro": "t3.nano",
    # m5 general purpose
    "m5.24xlarge": "m5.16xlarge",
    "m5.16xlarge": "m5.12xlarge",
    "m5.12xlarge": "m5.8xlarge",
    "m5.8xlarge": "m5.4xlarge",
    "m5.4xlarge": "m5.2xlarge",
    "m5.2xlarge": "m5.xlarge",
    "m5.xlarge": "m5.large",
    # c5 compute optimised
    "c5.18xlarge": "c5.12xlarge",
    "c5.12xlarge": "c5.9xlarge",
    "c5.9xlarge": "c5.4xlarge",
    "c5.4xlarge": "c5.2xlarge",
    "c5.2xlarge": "c5.xlarge",
    "c5.xlarge": "c5.large",
    # r5 memory optimised
    "r5.24xlarge": "r5.16xlarge",
    "r5.16xlarge": "r5.12xlarge",
    "r5.12xlarge": "r5.8xlarge",
    "r5.8xlarge": "r5.4xlarge",
    "r5.4xlarge": "r5.2xlarge",
    "r5.2xlarge": "r5.xlarge",
    "r5.xlarge": "r5.large",
}

# Price List ``pricing`` endpoints only exist in these regions; we pin to the
# first one for every lookup regardless of the scanned region.
_PRICING_API_REGION = "us-east-1"


class AwsCostProvider(CostProvider):
    """AWS implementation of the :class:`CostProvider` contract."""

    actual_cost_tier: DataTier = DataTier.TIER2_ENRICHED
    list_price_tier: DataTier = DataTier.TIER1_NATIVE

    def __init__(
        self,
        account_id: str,
        region: str,
        *,
        session: Any | None = None,
        ce_client: Any | None = None,
        pricing_client: Any | None = None,
    ) -> None:
        """Initialise the provider.

        Args:
            account_id: AWS account id (used for logging/scoping only).
            region: Default region for resources that do not carry their own.
            session: Optional pre-built ``boto3.Session`` reused from the
                adapter so credentials are never re-derived or hardcoded.
            ce_client: Injectable Cost Explorer client (tests). Defaults to a
                lazily created ``ce`` client from *session*.
            pricing_client: Injectable Price List client (tests). Defaults to a
                lazily created ``pricing`` client pinned to ``us-east-1``.
        """
        self.account_id = account_id
        self.region = region
        self._session = session
        self._ce_client = ce_client
        self._pricing_client = pricing_client
        # (sku, region) -> monthly USD (or per-GB for the ebs_gb:* keys).
        self._cache: dict[tuple[str, str], float] = {}

    # -- client helpers -----------------------------------------------------

    def _get_ce(self) -> Any:
        if self._ce_client is None:
            if self._session is None:
                raise RuntimeError("No boto3 session available for Cost Explorer")
            self._ce_client = self._session.client("ce")
        return self._ce_client

    def _get_pricing(self) -> Any:
        if self._pricing_client is None:
            if self._session is None:
                raise RuntimeError("No boto3 session available for Price List API")
            self._pricing_client = self._session.client(
                "pricing", region_name=_PRICING_API_REGION,
            )
        return self._pricing_client

    # -- actual cost --------------------------------------------------------

    async def _fetch_actual_cost(
        self, resource_ids: list[str], window: CostWindow
    ) -> dict[str, float]:
        """Query Cost Explorer for amortized monthly cost per resource."""
        loop = asyncio.get_running_loop()
        ce = self._get_ce()
        start = window.start.strftime("%Y-%m-%d")
        # Cost Explorer ``End`` is exclusive; advance one day past the window.
        end = (window.end.date() + timedelta(days=1)).strftime("%Y-%m-%d")

        def _call() -> dict[str, Any]:
            result: dict[str, Any] = ce.get_cost_and_usage(
                TimePeriod={"Start": start, "End": end},
                Granularity="MONTHLY",
                Metrics=["AmortizedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "RESOURCE_ID"}],
            )
            return result

        response = await loop.run_in_executor(None, _call)

        cost_map: dict[str, float] = {}
        for period in response.get("ResultsByTime", []) or []:
            for group in period.get("Groups", []) or []:
                keys = group.get("Keys") or []
                rid = keys[0] if keys else ""
                if not rid:
                    continue
                amount = (
                    group.get("Metrics", {})
                    .get("AmortizedCost", {})
                    .get("Amount", "0")
                )
                cost_map[rid.lower()] = cost_map.get(rid.lower(), 0.0) + float(amount)
        logger.info("Fetched AWS cost data for %d resources", len(cost_map))
        return cost_map

    # -- list price ---------------------------------------------------------

    async def _fetch_list_price(self, sku: str, region: str) -> float | None:
        """Resolve a logical AWS *sku* to a monthly USD list price.

        Supported sku encodings:
          * ``ebs:<volumeApiName>:<size_gb>`` -> per-GB-month price x size.
          * ``ec2:<instanceType>``           -> hourly on-demand x 730.
          * ``eip:idle``                     -> idle public IPv4 hourly x 730.

        Falls back to the static catalog (logged) when the Price List API
        misses; returns ``None`` when no price is obtainable.
        """
        parts = sku.split(":")
        kind = parts[0]

        if kind == "ebs":
            volume_type = parts[1] if len(parts) > 1 else ""
            size_gb = float(parts[2]) if len(parts) > 2 and parts[2] else 0.0
            per_gb = await self._ebs_per_gb_month(volume_type, region)
            if per_gb is not None and size_gb:
                return round(per_gb * size_gb, 2)
            fallback = aws_ebs_monthly_usd(volume_type, size_gb)
            if fallback > 0:
                logger.warning(
                    "EBS list price: using static catalog fallback for %s/%s",
                    volume_type, region,
                )
                return fallback
            return None

        if kind == "ec2":
            instance_type = parts[1] if len(parts) > 1 else ""
            return await self._ec2_instance_monthly(instance_type, region)

        if kind == "eip":
            live = await self._idle_eip_monthly(region)
            if live is not None and live > 0:
                return live
            fallback = aws_eip_unattached_monthly_usd()
            logger.warning(
                "Idle EIP list price: using static catalog fallback for %s",
                region,
            )
            return fallback

        return None

    # -- Price List parsing helpers ----------------------------------------

    async def _get_products(self, service_code: str, filters: dict[str, str]) -> list[str]:
        """Call ``pricing.get_products`` in an executor; return raw PriceList."""
        loop = asyncio.get_running_loop()

        def _call() -> list[str]:
            pricing = self._get_pricing()
            response = pricing.get_products(
                ServiceCode=service_code,
                Filters=[
                    {"Type": "TERM_MATCH", "Field": field, "Value": value}
                    for field, value in filters.items()
                ],
                MaxResults=100,
            )
            return response.get("PriceList", []) or []

        try:
            return await loop.run_in_executor(None, _call)
        except Exception as exc:  # noqa: BLE001 -- pricing must never crash a scan
            logger.warning(
                "Price List query failed for %s %s: %s", service_code, filters, exc,
            )
            return []

    @staticmethod
    def _parse_min_ondemand_usd(price_list: list[str]) -> float | None:
        """Return the smallest positive on-demand USD price across dimensions."""
        best: float | None = None
        for raw in price_list:
            try:
                data = json.loads(raw)
            except (TypeError, ValueError):
                continue
            on_demand = data.get("terms", {}).get("OnDemand", {})
            for term in on_demand.values():
                for dimension in term.get("priceDimensions", {}).values():
                    usd = dimension.get("pricePerUnit", {}).get("USD")
                    if usd is None:
                        continue
                    try:
                        value = float(usd)
                    except (TypeError, ValueError):
                        continue
                    if value > 0 and (best is None or value < best):
                        best = value
        return best

    async def _ebs_per_gb_month(self, volume_type: str, region: str) -> float | None:
        """Live per-GB-month price for an EBS volume type, cached."""
        key = (f"ebs_gb:{volume_type}", region.lower())
        cached = self._cache.get(key)
        if cached is not None and cached > 0:
            return cached
        items = await self._get_products(
            "AmazonEC2",
            {
                "regionCode": region,
                "volumeApiName": volume_type,
                "productFamily": "Storage",
            },
        )
        price = self._parse_min_ondemand_usd(items)
        if price is not None and price > 0:
            self._cache[key] = price
            return price
        return None

    async def _ec2_instance_monthly(self, instance_type: str, region: str) -> float | None:
        """Live monthly price for a Linux on-demand EC2 instance, cached."""
        key = (f"ec2:{instance_type}", region.lower())
        cached = self._cache.get(key)
        if cached is not None and cached > 0:
            return cached
        items = await self._get_products(
            "AmazonEC2",
            {
                "regionCode": region,
                "instanceType": instance_type,
                "operatingSystem": "Linux",
                "tenancy": "Shared",
                "preInstalledSw": "NA",
                "capacitystatus": "Used",
                "productFamily": "Compute Instance",
            },
        )
        hourly = self._parse_min_ondemand_usd(items)
        if hourly is None or hourly <= 0:
            return None
        monthly = round(hourly * HOURS_PER_MONTH, 2)
        self._cache[key] = monthly
        return monthly

    async def _idle_eip_monthly(self, region: str) -> float | None:
        """Live monthly price for an idle public IPv4 address, cached."""
        key = ("eip:idle", region.lower())
        cached = self._cache.get(key)
        if cached is not None and cached > 0:
            return cached
        items = await self._get_products(
            "AmazonVPC",
            {
                "regionCode": region,
                "productFamily": "Public IPv4 Address",
            },
        )
        hourly = self._parse_min_ondemand_usd(items)
        if hourly is None or hourly <= 0:
            return None
        monthly = round(hourly * HOURS_PER_MONTH, 2)
        self._cache[key] = monthly
        return monthly

    # -- rightsizing --------------------------------------------------------

    def next_instance_size_down(self, instance_type: str) -> str | None:
        """Return the recommended smaller instance type, or ``None``."""
        return _EC2_NEXT_SIZE_DOWN.get(instance_type)

    async def estimate_ec2_rightsizing_savings(
        self, instance_type: str, region: str
    ) -> float:
        """Estimate monthly savings from resizing an EC2 instance one size down.

        Computes ``current_price - recommended_smaller_price`` using live
        Price List data. Returns ``0.0`` when the type is unknown, has no
        smaller type, or either price is unavailable -- never negative.
        """
        smaller = self.next_instance_size_down(instance_type)
        if not smaller:
            return 0.0
        current = await self._ec2_instance_monthly(instance_type, region)
        recommended = await self._ec2_instance_monthly(smaller, region)
        if current is None or recommended is None:
            return 0.0
        return round(max(0.0, current - recommended), 2)

