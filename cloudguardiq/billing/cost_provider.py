"""CloudGuardIQ -- provider-agnostic cost abstraction.

This module defines the :class:`CostProvider` contract that every cloud
adapter's cost layer implements. It deliberately mirrors the design of
:class:`cloudguardiq.adapters.base.AdapterBase`: a thin, well-defined seam
that is the ONLY place allowed to talk to a cloud billing/pricing API.

Two tiers, aligned with the FinOps Open Cost & Usage Specification (FOCUS)
and the project's :class:`~cloudguardiq.core.enums.DataTier` model:

* **Actual cost** (``get_actual_cost``) -- the real, billed/effective cost
  per resource pulled from the provider's billing API (Azure Cost
  Management, AWS Cost Explorer, GCP BigQuery billing export). This is the
  authoritative ``EffectiveCost`` signal and maps to Tier-2/Tier-3 data.
* **List price** (``get_list_price``) -- the public catalog price for a SKU
  in a region (Azure Retail Prices, AWS Price List, GCP Cloud Billing
  Catalog). A strong lower bound used when actual cost is unavailable and
  maps to Tier-1 native data.

Both public methods are wrapped so that any provider failure degrades
gracefully: ``get_actual_cost`` returns ``{}`` and ``get_list_price``
returns the supplied default (or ``0.0``). A billing/pricing outage must
never propagate as an unhandled exception or crash a scan.
"""

from __future__ import annotations

import abc
import calendar
import logging
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict

from cloudguardiq.core.enums import DataTier
from cloudguardiq.core.models import FocusCostRecord

logger = logging.getLogger(__name__)

# Hours in an average month -- the standard convention for converting an
# hourly meter (public IP, load balancer, NAT gateway, VM) to a per-month
# figure. Shared by every provider so numbers are comparable across clouds.
HOURS_PER_MONTH: float = 730.0

# Supported billing windows. ``last_full_month`` is the default because a
# complete calendar month is a closed billing period (no partial-month
# skew); ``trailing_30d`` is offered for dashboards that want a rolling view.
CostWindowName = Literal["last_full_month", "trailing_30d"]


class CostWindow(BaseModel):
    """A normalized billing window shared by every cost provider.

    Centralising the date math here fixes the historical bug where the
    Azure scanner summed spend from the 1st of *last* month through *today*
    (1-2 months of cost mislabelled as one month). All providers resolve
    their query period from this single source of truth.
    """

    model_config = ConfigDict(frozen=True)

    name: CostWindowName
    start: datetime
    end: datetime
    days: int

    @classmethod
    def resolve(
        cls,
        name: CostWindowName,
        *,
        now: datetime | None = None,
    ) -> CostWindow:
        """Resolve a named window into concrete ``start``/``end`` timestamps.

        Args:
            name: ``"last_full_month"`` or ``"trailing_30d"``.
            now: Reference instant (defaults to current UTC time). Injectable
                for deterministic tests.

        Returns:
            A frozen :class:`CostWindow`.

        Raises:
            ValueError: If *name* is not a supported window.
        """
        ref = now or datetime.now(timezone.utc)

        if name == "last_full_month":
            first_of_this_month = ref.replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            )
            last_prev = first_of_this_month - timedelta(days=1)
            start = last_prev.replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            )
            month_len = calendar.monthrange(start.year, start.month)[1]
            end = start.replace(day=month_len, hour=23, minute=59, second=59)
            return cls(name=name, start=start, end=end, days=month_len)

        if name == "trailing_30d":
            start = ref - timedelta(days=30)
            return cls(name=name, start=start, end=ref, days=30)

        raise ValueError(f"Unsupported cost window: {name!r}")


class CostProvider(abc.ABC):
    """Abstract cost/pricing seam for a single cloud provider.

    Concrete subclasses implement the two protected ``_fetch_*`` template
    methods that talk to the provider APIs. The public ``get_*`` methods
    add the cross-cutting concerns (empty-input short-circuit, id
    normalisation, and graceful degradation) so individual providers do not
    each re-implement that boilerplate.
    """

    #: Data tier stamped on snapshots whose cost came from the billing API.
    actual_cost_tier: DataTier = DataTier.TIER2_ENRICHED
    #: Data tier stamped on snapshots whose cost came from the price catalog.
    list_price_tier: DataTier = DataTier.TIER1_NATIVE

    # -- abstract template methods -----------------------------------------

    @abc.abstractmethod
    async def _fetch_actual_cost(
        self, resource_ids: list[str], window: CostWindow
    ) -> dict[str, float]:
        """Return ``resource_id -> monthly USD`` from the billing API.

        Implementations may assume ``resource_ids`` is non-empty. Any
        exception raised here is caught by :meth:`get_actual_cost`.
        """

    @abc.abstractmethod
    async def _fetch_list_price(self, sku: str, region: str) -> float | None:
        """Return the monthly USD list price for *sku* in *region*.

        Return ``None`` on a miss. Any exception raised here is caught by
        :meth:`get_list_price`.
        """

    @abc.abstractmethod
    async def _fetch_cost_and_usage(
        self, window: CostWindow
    ) -> list[FocusCostRecord]:
        """Return FOCUS-normalized cost/usage rows for *window*.

        Implementations query the provider's billing API (Azure Cost
        Management, AWS Cost Explorer, GCP BigQuery export) and map each row
        to a :class:`~cloudguardiq.core.models.FocusCostRecord`. Any exception
        raised here is caught by :meth:`get_cost_and_usage`.
        """

    # -- public API --------------------------------------------------------

    async def get_actual_cost(
        self,
        resource_ids: list[str],
        *,
        window: CostWindowName = "last_full_month",
    ) -> dict[str, float]:
        """Return billed monthly cost per resource (best-effort).

        Args:
            resource_ids: Provider resource ids to price.
            window: Billing window to aggregate over.

        Returns:
            Mapping of lower-cased resource id to monthly USD. Empty dict on
            any error or when *resource_ids* is empty -- cost is enrichment
            only and never a hard dependency.
        """
        if not resource_ids:
            return {}
        resolved = CostWindow.resolve(window)
        try:
            raw = await self._fetch_actual_cost(resource_ids, resolved)
        except Exception:  # noqa: BLE001 -- enrichment must never crash a scan
            logger.warning(
                "%s actual-cost lookup failed -- continuing without cost data",
                type(self).__name__,
                exc_info=True,
            )
            return {}
        return {str(rid).lower(): float(cost) for rid, cost in raw.items()}

    async def get_list_price(
        self,
        sku: str,
        region: str,
        *,
        default: float | None = None,
    ) -> float:
        """Return the monthly USD list price for *sku* in *region*.

        Args:
            sku: Logical SKU key understood by the provider implementation.
            region: Provider region (case-insensitive).
            default: Value returned on a miss or error. ``0.0`` if omitted.

        Returns:
            Monthly USD list price, or *default* / ``0.0`` when unavailable.
        """
        fallback = default if default is not None else 0.0
        try:
            price = await self._fetch_list_price(sku, region)
        except Exception:  # noqa: BLE001 -- pricing must never crash a scan
            logger.warning(
                "%s list-price lookup failed for %s/%s",
                type(self).__name__,
                sku,
                region,
                exc_info=True,
            )
            return fallback
        if price is None or price <= 0:
            return fallback
        return float(price)


    async def get_cost_and_usage(
        self,
        *,
        window: CostWindowName = "last_full_month",
    ) -> list[FocusCostRecord]:
        """Return FOCUS-normalized cost/usage rows (best-effort).

        Args:
            window: Billing window to aggregate over.

        Returns:
            A list of :class:`~cloudguardiq.core.models.FocusCostRecord`.
            Empty list on any error -- billing ingestion is enrichment only
            and must never crash a scan or pipeline run.
        """
        resolved = CostWindow.resolve(window)
        try:
            return await self._fetch_cost_and_usage(resolved)
        except Exception:  # noqa: BLE001 -- ingestion must never crash callers
            logger.warning(
                "%s cost-and-usage ingestion failed -- returning no FOCUS rows",
                type(self).__name__,
                exc_info=True,
            )
            return []


class NullCostProvider(CostProvider):
    """Safe default that reports no cost data.

    Used wherever a real provider has not been wired up yet so callers can
    depend on the :class:`CostProvider` contract unconditionally.
    """

    async def _fetch_actual_cost(
        self, resource_ids: list[str], window: CostWindow
    ) -> dict[str, float]:
        """Return no actual-cost data."""
        return {}

    async def _fetch_list_price(self, sku: str, region: str) -> float | None:
        """Return no list price."""
        return None

    async def _fetch_cost_and_usage(
        self, window: CostWindow
    ) -> list[FocusCostRecord]:
        """Return no FOCUS cost rows."""
        return []

