"""CloudGuardIQ -- Azure cost provider.

Concrete :class:`~cloudguardiq.billing.cost_provider.CostProvider` for Azure.
It is the single seam that talks to Azure Cost Management (actual billed
cost) and the Azure Retail Prices catalog (list price, via the shared
:class:`~cloudguardiq.billing.pricing.PricingService`).

Design notes
------------
* **Actual cost** is queried with ``query.usage`` / ``ActualCost`` grouped by
  ``ResourceId`` over a FinOps-standard window (default: last full calendar
  month). Throttling (HTTP 429) is retried with exponential backoff; any
  other failure degrades to ``{}`` -- Cost Management is never a hard
  dependency.
* **List price** delegates to the in-process ``PricingService`` cache (Azure
  Retail Prices). No dollar amount is hardcoded here.
* **Rightsizing** estimates VM savings as the live price delta between the
  current SKU and the recommended smaller SKU, replacing the old flat
  ``cost_monthly * 0.5`` heuristic.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from functools import partial
from typing import Any

from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.mgmt.costmanagement import CostManagementClient
from azure.mgmt.costmanagement.models import (
    ExportType,
    QueryAggregation,
    QueryDataset,
    QueryDefinition,
    QueryGrouping,
    QueryTimePeriod,
    TimeframeType,
)

from cloudguardiq.billing.cost_provider import CostProvider, CostWindow
from cloudguardiq.billing.pricing import PricingService, get_pricing_service
from cloudguardiq.core.enums import CloudProvider
from cloudguardiq.core.models import FocusCostRecord

logger = logging.getLogger(__name__)


class AzureCostProvider(CostProvider):
    """Azure implementation of the :class:`CostProvider` contract."""

    def __init__(
        self,
        credential: TokenCredential | None,
        subscription_id: str,
        *,
        pricing_service: PricingService | None = None,
        client_factory: Callable[[TokenCredential], Any] | None = None,
    ) -> None:
        """Initialise the provider.

        Args:
            credential: Azure token credential. When ``None`` the provider
                reports no actual cost (list price still works).
            subscription_id: Subscription scope for Cost Management queries.
            pricing_service: Retail Prices cache. Defaults to the process
                singleton so list prices are shared across the app.
            client_factory: Factory for the Cost Management client. Injectable
                for tests; defaults to the real SDK client.
        """
        self._credential = credential
        self._subscription_id = subscription_id
        self._pricing = pricing_service or get_pricing_service()
        self._client_factory = client_factory

    # -- actual cost --------------------------------------------------------

    async def _fetch_actual_cost(
        self, resource_ids: list[str], window: CostWindow
    ) -> dict[str, float]:
        """Query Cost Management for billed monthly cost per resource."""
        if self._credential is None:
            logger.info("No Azure credential -- skipping actual-cost lookup")
            return {}

        loop = asyncio.get_running_loop()
        # Resolve the module-level client name at call time so tests can
        # patch ``CostManagementClient`` after the provider is built.
        factory = self._client_factory or CostManagementClient
        client = factory(self._credential)
        scope = f"/subscriptions/{self._subscription_id}"

        query_def = QueryDefinition(
            type=ExportType.ACTUAL_COST,
            timeframe=TimeframeType.CUSTOM,
            time_period=QueryTimePeriod(from_property=window.start, to=window.end),
            dataset=QueryDataset(
                granularity="None",
                aggregation={
                    "totalCost": QueryAggregation(name="Cost", function="Sum"),
                },
                grouping=[QueryGrouping(type="Dimension", name="ResourceId")],
            ),
        )

        response = await self._run_cost_query_with_retry(
            loop, partial(client.query.usage, scope, query_def),
        )

        cost_map: dict[str, float] = {}
        if response and getattr(response, "rows", None):
            for row in response.rows:
                if len(row) >= 2:
                    cost_map[str(row[1]).lower()] = float(row[0])
        logger.info("Fetched Azure cost data for %d resources", len(cost_map))
        return cost_map

    async def _run_cost_query_with_retry(
        self,
        loop: asyncio.AbstractEventLoop,
        call: Any,
        max_attempts: int = 5,
        base_delay: float = 2.0,
        max_delay: float = 60.0,
    ) -> Any:
        """Invoke the Cost Management query with exponential backoff on 429s.

        Azure Cost Management enforces strict per-subscription rate limits.
        When a 429 is returned, we honor the ``Retry-After`` header if
        present, otherwise apply exponential backoff capped at ``max_delay``.
        Non-throttling errors propagate immediately to the outer handler.
        """
        attempt = 0
        while True:
            attempt += 1
            try:
                return await loop.run_in_executor(None, call)
            except HttpResponseError as exc:
                status = getattr(exc, "status_code", None)
                if status != 429 or attempt >= max_attempts:
                    raise
                retry_after = base_delay * (2 ** (attempt - 1))
                response = getattr(exc, "response", None)
                headers = getattr(response, "headers", None) or {}
                header_value = headers.get("Retry-After") or headers.get("retry-after")
                if header_value:
                    with contextlib.suppress(TypeError, ValueError):
                        retry_after = float(header_value)
                retry_after = min(retry_after, max_delay)
                logger.warning(
                    "Cost Management API returned 429 (attempt %d/%d); retrying in %.1fs",
                    attempt, max_attempts, retry_after,
                )
                await asyncio.sleep(retry_after)

    # -- FOCUS cost and usage ----------------------------------------------

    async def _fetch_cost_and_usage(
        self, window: CostWindow
    ) -> list[FocusCostRecord]:
        """Query Cost Management and map rows to FOCUS records.

        Groups actual cost by ResourceId, ServiceName, ResourceType and
        ResourceLocation so each row carries enough dimensions to populate a
        :class:`FocusCostRecord`. Rows are mapped by *column name* (robust to
        column ordering) with a positional fallback.
        """
        if self._credential is None:
            logger.info("No Azure credential -- skipping cost-and-usage lookup")
            return []

        loop = asyncio.get_running_loop()
        factory = self._client_factory or CostManagementClient
        client = factory(self._credential)
        scope = f"/subscriptions/{self._subscription_id}"

        query_def = QueryDefinition(
            type=ExportType.ACTUAL_COST,
            timeframe=TimeframeType.CUSTOM,
            time_period=QueryTimePeriod(from_property=window.start, to=window.end),
            dataset=QueryDataset(
                granularity="None",
                aggregation={
                    "totalCost": QueryAggregation(name="Cost", function="Sum"),
                },
                grouping=[
                    QueryGrouping(type="Dimension", name="ResourceId"),
                    QueryGrouping(type="Dimension", name="ServiceName"),
                    QueryGrouping(type="Dimension", name="ResourceType"),
                    QueryGrouping(type="Dimension", name="ResourceLocation"),
                ],
            ),
        )

        response = await self._run_cost_query_with_retry(
            loop, partial(client.query.usage, scope, query_def),
        )
        return self._rows_to_focus(response, window)

    def _rows_to_focus(
        self, response: Any, window: CostWindow
    ) -> list[FocusCostRecord]:
        """Map a Cost Management query response into FOCUS records."""
        rows = getattr(response, "rows", None) or []
        columns = getattr(response, "columns", None) or []
        names = [getattr(c, "name", "") for c in columns]

        def idx(name: str) -> int:
            return names.index(name) if name in names else -1

        i_cost = idx("Cost") if "Cost" in names else idx("PreTaxCost")
        i_rid = idx("ResourceId")
        i_svc = idx("ServiceName")
        i_rtype = idx("ResourceType")
        i_loc = idx("ResourceLocation")
        i_cur = idx("Currency")

        period = window.start.strftime("%Y-%m")
        records: list[FocusCostRecord] = []
        for row in rows:
            # Positional fallback matches the grouping order declared above.
            cost = float(row[i_cost]) if i_cost >= 0 else float(row[0])
            rid = str(row[i_rid]) if i_rid >= 0 else (str(row[1]) if len(row) > 1 else "")
            service = str(row[i_svc]) if i_svc >= 0 and row[i_svc] is not None else ""
            rtype = str(row[i_rtype]) if i_rtype >= 0 and row[i_rtype] is not None else ""
            region = str(row[i_loc]) if i_loc >= 0 and row[i_loc] is not None else ""
            currency = str(row[i_cur]) if i_cur >= 0 and row[i_cur] is not None else "USD"
            records.append(
                FocusCostRecord(
                    billing_period=period,
                    charge_period_start=window.start,
                    charge_period_end=window.end,
                    billed_cost=cost,
                    effective_cost=cost,
                    list_cost=cost,
                    billing_currency=currency,
                    provider=CloudProvider.AZURE,
                    billing_account_id=self._subscription_id,
                    sub_account_id=self._subscription_id,
                    service_name=service,
                    resource_id=rid.lower(),
                    resource_type=rtype,
                    region=region,
                    data_tier=self.actual_cost_tier,
                )
            )
        logger.info("Mapped %d Azure FOCUS cost records", len(records))
        return records

    # -- list price ---------------------------------------------------------

    async def _fetch_list_price(self, sku: str, region: str) -> float | None:
        """Return the cached Retail Prices list price, or ``None`` on a miss."""
        price = self._pricing.get_price(sku, region, default=0.0)
        return price if price > 0 else None

    # -- rightsizing --------------------------------------------------------

    async def estimate_vm_rightsizing_savings(
        self, vm_size: str, region: str
    ) -> float:
        """Estimate monthly savings from resizing a VM one size down.

        Computes ``current_price - recommended_smaller_price`` using live
        Retail Prices. Returns ``0.0`` when the size is unknown, has no
        smaller SKU, or either price is unavailable -- never a negative value.
        """
        smaller = self._pricing.next_size_down(vm_size)
        if not smaller:
            return 0.0
        current = await self._pricing.get_vm_size_price(vm_size, region)
        recommended = await self._pricing.get_vm_size_price(smaller, region)
        if current is None or recommended is None:
            return 0.0
        return round(max(0.0, current - recommended), 2)
