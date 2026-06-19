"""Unit tests: unit-economics (cost per allocation unit)."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from cloudguardiq.core.models import FocusCostRecord
from cloudguardiq.finops.unit_economics import (
    UnitEconomics,
    compute_unit_economics,
)

TENANT = "tenant-ue"
SUB = "sub-ue"


def _row(day: date, cost: float) -> FocusCostRecord:
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return FocusCostRecord(
        tenant_id=TENANT,
        billing_period=f"{day.year}-{day.month:02d}",
        charge_period_start=start,
        charge_period_end=start,
        charge_category="Usage",
        effective_cost=cost,
        sub_account_id=SUB,
        service_category="Compute",
    )


def test_compute_unit_economics_basic() -> None:
    as_of = date(2026, 5, 10)
    records = [_row(as_of - timedelta(days=o), 100.0) for o in range(10)]
    result = compute_unit_economics(
        records, units=200.0, unit_label="customers", as_of=as_of
    )
    assert isinstance(result, UnitEconomics)
    assert result.units == 200.0
    assert result.unit_label == "customers"
    assert result.total_cost == 1000.0
    assert result.cost_per_unit == 5.0  # $1000 / 200 customers
    # Projected month-end (flat $100/day over 31 days = $3100) / 200 = $15.5
    assert abs(result.projected_cost_per_unit - 15.5) < 0.5


def test_compute_unit_economics_zero_units_is_safe() -> None:
    result = compute_unit_economics([], units=0.0)
    assert result.cost_per_unit == 0.0
    assert result.projected_cost_per_unit == 0.0
    assert result.total_cost == 0.0
