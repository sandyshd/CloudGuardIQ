"""Unit tests: budget actual-vs-budget and forecast-vs-budget detection."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from cloudguardiq.core.models import FocusCostRecord
from cloudguardiq.finops.budgets import (
    Budget,
    BudgetStatus,
    evaluate_budgets,
)

TENANT = "tenant-bg"
SUB = "sub-bg"


def _row(day: date, cost: float, tags: dict[str, str] | None = None,
         service: str = "Compute") -> FocusCostRecord:
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


def _budget(amount: float, *, dimension: str = "sub_account",
            dimension_value: str = "") -> Budget:
    return Budget(
        budget_id="b1",
        tenant_id=TENANT,
        subscription_id=SUB,
        name="Monthly compute",
        dimension=dimension,
        dimension_value=dimension_value,
        amount_monthly=amount,
        alert_threshold_pct=0.8,
    )


def test_budget_actual_breach() -> None:
    # 10 days at $50 = $500 month-to-date, budget $400 -> already breached.
    as_of = date(2026, 5, 10)
    records = [_row(as_of - timedelta(days=o), 50.0) for o in range(10)]
    statuses = evaluate_budgets(records, [_budget(400.0)], as_of=as_of)
    assert len(statuses) == 1
    s = statuses[0]
    assert isinstance(s, BudgetStatus)
    assert s.actual_cost == 500.0
    assert s.status == "BREACH"
    assert s.pct_used > 1.0


def test_budget_projected_breach() -> None:
    # 5 days at $50 = $250 MTD, budget $400. Flat $50/day over 31-day May
    # projects to ~$1550 -> projected breach (actual still under budget).
    as_of = date(2026, 5, 5)
    records = [_row(as_of - timedelta(days=o), 50.0) for o in range(5)]
    statuses = evaluate_budgets(records, [_budget(400.0)], as_of=as_of)
    s = statuses[0]
    assert s.actual_cost == 250.0
    assert s.status == "PROJECTED_BREACH"
    assert s.projected_pct > 1.0
    assert s.pct_used < 1.0


def test_budget_ok_and_warn() -> None:
    as_of = date(2026, 5, 31)  # last day -> projection == actual
    records = [_row(as_of - timedelta(days=o), 10.0) for o in range(31)]
    # $310 actual. Budget $1000 -> OK.
    ok = evaluate_budgets(records, [_budget(1000.0)], as_of=as_of)[0]
    assert ok.status == "OK"
    # Budget $360 -> 86% used, above 80% threshold but not breached -> WARN.
    warn = evaluate_budgets(records, [_budget(360.0)], as_of=as_of)[0]
    assert warn.status == "WARN"


def test_budget_scoped_to_tag_dimension() -> None:
    as_of = date(2026, 5, 31)
    records = (
        [_row(as_of - timedelta(days=o), 10.0, tags={"team": "data"})
         for o in range(31)]
        + [_row(as_of - timedelta(days=o), 99.0, tags={"team": "other"})
           for o in range(31)]
    )
    budget = _budget(400.0, dimension="tag:team", dimension_value="data")
    s = evaluate_budgets(records, [budget], as_of=as_of)[0]
    # Only the "data" team's $310 counts against this budget.
    assert s.actual_cost == 310.0
    assert s.status == "OK"


def test_evaluate_budgets_emits_findings_on_breach() -> None:
    as_of = date(2026, 5, 10)
    records = [_row(as_of - timedelta(days=o), 50.0) for o in range(10)]
    statuses = evaluate_budgets(records, [_budget(400.0)], as_of=as_of)
    findings = [f for s in statuses for f in s.findings]
    assert any(f.rule_id == "FIN-BG-001" for f in findings)


def test_evaluate_budgets_empty() -> None:
    assert evaluate_budgets([], [], as_of=date(2026, 5, 10)) == []
