"""Unit tests: spend forecasting over a deterministic FOCUS series."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from cloudguardiq.core.models import FocusCostRecord
from cloudguardiq.finops.forecasting import SpendForecast, forecast_spend

TENANT = "tenant-fc"
SUB = "sub-fc"


def _row(day: date, cost: float, *, service: str = "Compute",
         tags: dict[str, str] | None = None) -> FocusCostRecord:
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return FocusCostRecord(
        tenant_id=TENANT,
        billing_period=f"{day.year}-{day.month:02d}",
        charge_period_start=start,
        charge_period_end=start,
        charge_category="Usage",
        effective_cost=cost,
        sub_account_id=SUB,
        service_category=service,
        service_name=service,
        tags=tags or {},
    )


def _constant_series(end: date, days: int, daily: float) -> list[FocusCostRecord]:
    return [_row(end - timedelta(days=offset), daily) for offset in range(days)]


def test_forecast_constant_series_projects_full_month() -> None:
    # 40 trailing days at a flat $10/day, "today" = 2026-05-15.
    as_of = date(2026, 5, 15)
    records = _constant_series(as_of, 40, 10.0)

    forecasts = forecast_spend(records, dimension="sub_account", as_of=as_of)
    assert len(forecasts) == 1
    f = forecasts[0]
    assert isinstance(f, SpendForecast)
    assert f.key == SUB
    assert abs(f.trailing_daily_avg - 10.0) < 1e-6

    # Month-to-date = 15 days * 10 = 150.
    assert abs(f.month_to_date_cost - 150.0) < 1e-6
    # Month-end = 31 days (May) * 10 = 310 within tolerance.
    assert abs(f.projected_month_end_cost - 310.0) < 0.5
    # Next month (June, 30 days) * 10 = 300.
    assert abs(f.projected_next_month_cost - 300.0) < 0.5


def test_forecast_per_service_dimension() -> None:
    as_of = date(2026, 5, 20)
    records = (
        _constant_series(as_of, 30, 5.0)  # Compute @ $5/day
        + [_row(as_of - timedelta(days=o), 2.0, service="Storage")
           for o in range(30)]
    )
    forecasts = {f.key: f for f in
                 forecast_spend(records, dimension="service", as_of=as_of)}
    assert "Compute" in forecasts
    assert "Storage" in forecasts
    assert abs(forecasts["Compute"].trailing_daily_avg - 5.0) < 1e-6
    assert abs(forecasts["Storage"].trailing_daily_avg - 2.0) < 1e-6


def test_forecast_tag_dimension_skips_untagged() -> None:
    as_of = date(2026, 5, 10)
    records = (
        [_row(as_of - timedelta(days=o), 4.0, tags={"team": "data"})
         for o in range(20)]
        + [_row(as_of - timedelta(days=o), 9.0) for o in range(20)]  # untagged
    )
    forecasts = forecast_spend(records, dimension="tag:team", as_of=as_of)
    assert len(forecasts) == 1
    assert forecasts[0].key == "data"
    assert abs(forecasts[0].trailing_daily_avg - 4.0) < 1e-6


def test_forecast_empty_records_returns_empty() -> None:
    assert forecast_spend([], dimension="sub_account") == []
