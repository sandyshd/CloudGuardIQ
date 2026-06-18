"""Spend forecasting over FOCUS cost records.

Pure functions only -- no cloud SDK, no I/O. The model is intentionally
simple and deterministic: a trailing daily average (trend) modulated by a
day-of-week seasonality baseline. Forecasts are produced per allocation
dimension (``sub_account`` / ``service`` / ``tag:<key>``) and expose both the
projected month-end and next-month spend.
"""

from __future__ import annotations

import calendar
from collections import defaultdict
from collections.abc import Iterable
from datetime import date, timedelta

from pydantic import BaseModel

from cloudguardiq.core.models import FocusCostRecord

DEFAULT_TRAILING_WINDOW_DAYS = 28


class SpendForecast(BaseModel):
    """Projected spend for a single allocation-dimension value."""

    dimension: str
    key: str
    observed_days: int = 0
    trailing_daily_avg: float = 0.0
    month_to_date_cost: float = 0.0
    projected_month_end_cost: float = 0.0
    projected_next_month_cost: float = 0.0


def _dimension_key(record: FocusCostRecord, dimension: str) -> str | None:
    """Return the grouping value for ``record`` under ``dimension``.

    Returns ``None`` when the row does not belong to the dimension (e.g. a
    ``tag:<key>`` dimension on an untagged row) so it is excluded.
    """
    if dimension == "sub_account":
        return record.sub_account_id
    if dimension == "service":
        return record.service_name or record.service_category
    if dimension.startswith("tag:"):
        tag_key = dimension.split(":", 1)[1]
        return record.tags.get(tag_key)
    return None


def _daily_series(
    records: Iterable[FocusCostRecord], dimension: str
) -> dict[str, dict[date, float]]:
    """Aggregate effective cost into per-key, per-day totals."""
    series: dict[str, dict[date, float]] = defaultdict(lambda: defaultdict(float))
    for record in records:
        key = _dimension_key(record, dimension)
        if key is None:
            continue
        day = record.charge_period_start.date()
        series[key][day] += record.effective_cost
    return series


def _next_month(year: int, month: int) -> tuple[int, int]:
    """Return the (year, month) immediately after the given month."""
    if month == 12:
        return year + 1, 1
    return year, month + 1


def _forecast_one(
    dimension: str,
    key: str,
    daily: dict[date, float],
    as_of: date,
    window: int,
) -> SpendForecast:
    """Forecast a single dimension value's series."""
    window_start = as_of - timedelta(days=window - 1)
    window_days = [d for d in daily if window_start <= d <= as_of]
    window_values = [daily[d] for d in window_days]
    trailing_avg = sum(window_values) / len(window_values) if window_values else 0.0

    # Day-of-week seasonality factor relative to the trailing average.
    dow_totals: dict[int, float] = defaultdict(float)
    dow_counts: dict[int, int] = defaultdict(int)
    for d in window_days:
        dow_totals[d.weekday()] += daily[d]
        dow_counts[d.weekday()] += 1

    def factor(weekday: int) -> float:
        if trailing_avg <= 0 or dow_counts[weekday] == 0:
            return 1.0
        return (dow_totals[weekday] / dow_counts[weekday]) / trailing_avg

    def predict(day: date) -> float:
        return trailing_avg * factor(day.weekday())

    # Month-to-date actuals for the as-of month.
    month_to_date = sum(
        cost
        for d, cost in daily.items()
        if d.year == as_of.year and d.month == as_of.month and d <= as_of
    )

    # Remaining days of the current month.
    days_in_month = calendar.monthrange(as_of.year, as_of.month)[1]
    remaining = 0.0
    for day_num in range(as_of.day + 1, days_in_month + 1):
        remaining += predict(date(as_of.year, as_of.month, day_num))
    projected_month_end = month_to_date + remaining

    # Full next month.
    ny, nm = _next_month(as_of.year, as_of.month)
    days_next = calendar.monthrange(ny, nm)[1]
    projected_next_month = sum(
        predict(date(ny, nm, day_num)) for day_num in range(1, days_next + 1)
    )

    return SpendForecast(
        dimension=dimension,
        key=key,
        observed_days=len(daily),
        trailing_daily_avg=round(trailing_avg, 2),
        month_to_date_cost=round(month_to_date, 2),
        projected_month_end_cost=round(projected_month_end, 2),
        projected_next_month_cost=round(projected_next_month, 2),
    )


def forecast_spend(
    records: Iterable[FocusCostRecord],
    *,
    dimension: str = "sub_account",
    as_of: date | None = None,
    window: int = DEFAULT_TRAILING_WINDOW_DAYS,
) -> list[SpendForecast]:
    """Forecast month-end and next-month spend per ``dimension`` value.

    ``as_of`` defaults to the latest charge date observed across all rows.
    Returns one :class:`SpendForecast` per dimension value, sorted by key.
    """
    series = _daily_series(records, dimension)
    if not series:
        return []

    if as_of is None:
        as_of = max(day for daily in series.values() for day in daily)

    return [
        _forecast_one(dimension, key, series[key], as_of, window)
        for key in sorted(series)
    ]
