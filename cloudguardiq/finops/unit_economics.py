"""Unit economics: cost per tenant-defined allocation unit.

Pure functions over FOCUS rows. Divides month-to-date and projected month-end
spend by a tenant-supplied unit count (e.g. active customers, transactions,
tenants served) to express cost efficiency. No cloud SDK, no I/O.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date

from pydantic import BaseModel

from cloudguardiq.core.models import FocusCostRecord
from cloudguardiq.finops.forecasting import forecast_spend


class UnitEconomics(BaseModel):
    """Cost-per-unit roll-up for a tenant-defined denominator."""

    unit_label: str = "unit"
    units: float = 0.0
    total_cost: float = 0.0
    projected_month_end_cost: float = 0.0
    cost_per_unit: float = 0.0
    projected_cost_per_unit: float = 0.0


def compute_unit_economics(
    records: Iterable[FocusCostRecord],
    *,
    units: float,
    unit_label: str = "unit",
    as_of: date | None = None,
) -> UnitEconomics:
    """Return month-to-date and projected cost per unit.

    ``units`` is the tenant-defined denominator. A non-positive ``units`` (or
    no data) yields a zeroed result rather than dividing by zero.
    """
    forecasts = forecast_spend(records, dimension="sub_account", as_of=as_of)
    total = sum(f.month_to_date_cost for f in forecasts)
    projected = sum(f.projected_month_end_cost for f in forecasts)

    cost_per_unit = total / units if units > 0 else 0.0
    projected_per_unit = projected / units if units > 0 else 0.0

    return UnitEconomics(
        unit_label=unit_label,
        units=units,
        total_cost=round(total, 2),
        projected_month_end_cost=round(projected, 2),
        cost_per_unit=round(cost_per_unit, 4),
        projected_cost_per_unit=round(projected_per_unit, 4),
    )
