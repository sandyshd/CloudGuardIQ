"""Budget tracking: actual-vs-budget and forecast-vs-budget with alerts.

Pure model-level logic over :class:`~cloudguardiq.core.models.FocusCostRecord`
plus persisted :class:`Budget` definitions. No cloud SDK, no I/O. Budgets are
scoped to an allocation dimension (whole sub-account, a service, or a tag
value); each is evaluated for its month-to-date actual and a projected
month-end (reusing the forecasting trend), emitting findings on breach or
projected breach.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import date, datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field

from cloudguardiq.core.enums import CloudProvider, Severity
from cloudguardiq.core.models import FindingResult, FocusCostRecord
from cloudguardiq.finops._common import build_finops_finding
from cloudguardiq.finops.forecasting import forecast_spend

RULE_BREACH = "FIN-BG-001"
RULE_PROJECTED_BREACH = "FIN-BG-002"

BudgetStatusValue = str  # "OK" | "WARN" | "BREACH" | "PROJECTED_BREACH"


class Budget(BaseModel):
    """A per-tenant spend budget scoped to an allocation dimension."""

    budget_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str = ""
    subscription_id: str = ""
    name: str = ""
    # ``sub_account`` | ``service`` | ``tag:<key>``.
    dimension: str = "sub_account"
    # Specific value to track ("" = the whole subscription / dimension).
    dimension_value: str = ""
    amount_monthly: float = 0.0
    alert_threshold_pct: float = 0.8
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class BudgetStatus(BaseModel):
    """Evaluated state of a budget for the current month."""

    budget_id: str
    name: str
    dimension: str
    dimension_value: str
    amount_monthly: float
    actual_cost: float = 0.0
    projected_month_end_cost: float = 0.0
    pct_used: float = 0.0
    projected_pct: float = 0.0
    status: BudgetStatusValue = "OK"
    findings: list[FindingResult] = Field(default_factory=list)


def _matches(record: FocusCostRecord, dimension: str, value: str) -> bool:
    """Return True when ``record`` belongs to the budget's dimension value."""
    if not value:
        return True
    if dimension == "sub_account":
        return record.sub_account_id == value
    if dimension == "service":
        return value in (record.service_name, record.service_category)
    if dimension.startswith("tag:"):
        tag_key = dimension.split(":", 1)[1].lower()
        lowered = {k.lower(): v for k, v in record.tags.items()}
        return lowered.get(tag_key) == value
    return False


def _evaluate_one(
    records: Sequence[FocusCostRecord],
    budget: Budget,
    as_of: date,
    provider: CloudProvider,
) -> BudgetStatus:
    """Evaluate a single budget against the filtered FOCUS rows."""
    scoped = [
        r for r in records if _matches(r, budget.dimension, budget.dimension_value)
    ]
    forecasts = forecast_spend(scoped, dimension="sub_account", as_of=as_of)
    actual = forecasts[0].month_to_date_cost if forecasts else 0.0
    projected = forecasts[0].projected_month_end_cost if forecasts else 0.0

    amount = budget.amount_monthly
    pct_used = actual / amount if amount > 0 else 0.0
    projected_pct = projected / amount if amount > 0 else 0.0

    findings: list[FindingResult] = []
    if amount > 0 and actual > amount:
        status = "BREACH"
        findings.append(
            _finding(
                RULE_BREACH,
                "Budget breached",
                budget,
                provider,
                actual - amount,
                f"Budget '{budget.name}' is breached: "
                f"${actual:,.2f} spent of ${amount:,.2f} "
                f"({pct_used:.0%}).",
                {"actual_cost": round(actual, 2), "amount_monthly": amount},
                Severity.HIGH,
            )
        )
    elif amount > 0 and projected > amount:
        status = "PROJECTED_BREACH"
        findings.append(
            _finding(
                RULE_PROJECTED_BREACH,
                "Budget projected to breach",
                budget,
                provider,
                projected - amount,
                f"Budget '{budget.name}' is projected to breach: "
                f"${projected:,.2f} forecast of ${amount:,.2f} "
                f"({projected_pct:.0%}).",
                {
                    "projected_month_end_cost": round(projected, 2),
                    "amount_monthly": amount,
                },
                Severity.MEDIUM,
            )
        )
    elif amount > 0 and pct_used >= budget.alert_threshold_pct:
        status = "WARN"
    else:
        status = "OK"

    return BudgetStatus(
        budget_id=budget.budget_id,
        name=budget.name,
        dimension=budget.dimension,
        dimension_value=budget.dimension_value,
        amount_monthly=amount,
        actual_cost=round(actual, 2),
        projected_month_end_cost=round(projected, 2),
        pct_used=round(pct_used, 4),
        projected_pct=round(projected_pct, 4),
        status=status,
        findings=findings,
    )


def _finding(
    rule_id: str,
    rule_name: str,
    budget: Budget,
    provider: CloudProvider,
    overage: float,
    description: str,
    evidence: dict[str, object],
    severity: Severity,
) -> FindingResult:
    """Build a budget alert finding."""
    full_evidence: dict[str, object] = {
        "budget_id": budget.budget_id,
        "dimension": budget.dimension,
        "dimension_value": budget.dimension_value,
        **evidence,
    }
    return build_finops_finding(
        rule_id=rule_id,
        rule_name=rule_name,
        provider=provider,
        subscription_id=budget.subscription_id,
        tenant_id=budget.tenant_id,
        resource_name=f"budget/{budget.budget_id}",
        description=description,
        evidence=full_evidence,
        estimated_impact_monthly_usd=max(overage, 0.0),
        finops_method="ESTIMATED",
        finops_confidence="MEDIUM",
        severity=severity,
    )


def evaluate_budgets(
    records: Iterable[FocusCostRecord],
    budgets: Iterable[Budget],
    *,
    as_of: date | None = None,
    provider: CloudProvider = CloudProvider.AZURE,
) -> list[BudgetStatus]:
    """Evaluate each budget's actual + projected spend for the current month."""
    materialized = list(records)
    budget_list = list(budgets)
    if not budget_list:
        return []
    if as_of is None:
        if materialized:
            as_of = max(r.charge_period_start.date() for r in materialized)
        else:
            as_of = datetime.now(timezone.utc).date()
    return [_evaluate_one(materialized, b, as_of, provider) for b in budget_list]
