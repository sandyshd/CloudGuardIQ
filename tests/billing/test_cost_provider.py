"""Tests for the provider-agnostic cost abstraction (Prompt 0 foundation)."""

from __future__ import annotations

import calendar
from datetime import datetime, timezone

import pytest

from cloudguardiq.billing.cost_provider import (
    HOURS_PER_MONTH,
    CostProvider,
    CostWindow,
    NullCostProvider,
)
from cloudguardiq.core.enums import DataTier


class TestCostWindow:
    """The shared billing window math used by every provider."""

    def test_last_full_month_is_previous_calendar_month(self) -> None:
        now = datetime(2026, 6, 16, 10, 30, tzinfo=timezone.utc)
        win = CostWindow.resolve("last_full_month", now=now)
        assert win.start == datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc)
        # End is the last day of May (inclusive period boundary).
        assert win.start.month == 5
        assert win.end.month == 5
        assert win.end.day == 31
        assert win.days == 31

    def test_last_full_month_handles_january_rollover(self) -> None:
        now = datetime(2026, 1, 5, tzinfo=timezone.utc)
        win = CostWindow.resolve("last_full_month", now=now)
        assert win.start == datetime(2025, 12, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert win.end.year == 2025
        assert win.end.month == 12
        assert win.end.day == 31
        assert win.days == 31

    def test_last_full_month_handles_february_length(self) -> None:
        now = datetime(2026, 3, 2, tzinfo=timezone.utc)
        win = CostWindow.resolve("last_full_month", now=now)
        assert win.start.month == 2
        assert win.days == calendar.monthrange(2026, 2)[1] == 28

    def test_trailing_30d_is_exactly_30_days(self) -> None:
        now = datetime(2026, 6, 16, 10, 30, tzinfo=timezone.utc)
        win = CostWindow.resolve("trailing_30d", now=now)
        assert win.end == now
        assert (win.end - win.start).days == 30
        assert win.days == 30

    def test_invalid_window_name_raises(self) -> None:
        with pytest.raises(ValueError):
            CostWindow.resolve("yesterday", now=datetime.now(timezone.utc))  # type: ignore[arg-type]

    def test_hours_per_month_constant(self) -> None:
        assert HOURS_PER_MONTH == 730.0


class _RaisingProvider(CostProvider):
    """Provider whose internals always blow up -- proves graceful degradation."""

    async def _fetch_actual_cost(
        self, resource_ids: list[str], window: CostWindow
    ) -> dict[str, float]:
        raise RuntimeError("billing API exploded")

    async def _fetch_list_price(self, sku: str, region: str) -> float | None:
        raise RuntimeError("pricing API exploded")


class _StubProvider(CostProvider):
    """Provider returning canned data for the happy path."""

    async def _fetch_actual_cost(
        self, resource_ids: list[str], window: CostWindow
    ) -> dict[str, float]:
        return {rid.lower(): 12.5 for rid in resource_ids}

    async def _fetch_list_price(self, sku: str, region: str) -> float | None:
        return 3.65


@pytest.mark.asyncio
class TestCostProviderContract:
    async def test_get_actual_cost_empty_ids_short_circuits(self) -> None:
        prov = _StubProvider()
        assert await prov.get_actual_cost([]) == {}

    async def test_get_actual_cost_lowercases_ids(self) -> None:
        prov = _StubProvider()
        out = await prov.get_actual_cost(["/SUBS/AbC"])
        assert out == {"/subs/abc": 12.5}

    async def test_get_actual_cost_degrades_to_empty_on_error(self) -> None:
        prov = _RaisingProvider()
        assert await prov.get_actual_cost(["a"]) == {}

    async def test_get_list_price_returns_value(self) -> None:
        prov = _StubProvider()
        assert await prov.get_list_price("public_ip_standard", "eastus") == 3.65

    async def test_get_list_price_degrades_to_default_on_error(self) -> None:
        prov = _RaisingProvider()
        assert await prov.get_list_price("x", "eastus", default=9.9) == 9.9

    async def test_get_list_price_degrades_to_zero_without_default(self) -> None:
        prov = _RaisingProvider()
        assert await prov.get_list_price("x", "eastus") == 0.0

    async def test_data_tier_hints(self) -> None:
        prov = _StubProvider()
        assert prov.actual_cost_tier == DataTier.TIER2_ENRICHED
        assert prov.list_price_tier == DataTier.TIER1_NATIVE


@pytest.mark.asyncio
class TestNullCostProvider:
    async def test_actual_cost_is_empty(self) -> None:
        assert await NullCostProvider().get_actual_cost(["a", "b"]) == {}

    async def test_list_price_uses_default(self) -> None:
        assert await NullCostProvider().get_list_price("x", "r", default=1.23) == 1.23

    async def test_list_price_zero_without_default(self) -> None:
        assert await NullCostProvider().get_list_price("x", "r") == 0.0
