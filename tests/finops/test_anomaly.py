"""Unit tests: statistical anomaly detection over FOCUS daily spend."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from cloudguardiq.core.models import FocusCostRecord
from cloudguardiq.finops.anomaly import (
    SpendAnomaly,
    detect_anomalies,
    evaluate_anomalies,
)

TENANT = "tenant-an"
SUB = "sub-an"
_BASE = date(2026, 5, 1)


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


def _stable_series_with_spike(spike_day: int, spike_cost: float
                              ) -> list[FocusCostRecord]:
    # 40 distinct days of ~$100/day with mild deterministic +/-$1 variance,
    # with the spike day replaced by a single high-cost row.
    rows: list[FocusCostRecord] = []
    for i in range(40):
        if i == spike_day:
            rows.append(_row(_BASE + timedelta(days=i), spike_cost))
        else:
            cost = 100.0 + (1.0 if i % 2 == 0 else -1.0)
            rows.append(_row(_BASE + timedelta(days=i), cost))
    return rows


def test_detect_anomalies_flags_injected_spike() -> None:
    records = _stable_series_with_spike(spike_day=39, spike_cost=500.0)
    anomalies = detect_anomalies(records, z_threshold=3.0)
    assert len(anomalies) >= 1
    a = anomalies[-1]
    assert isinstance(a, SpendAnomaly)
    assert a.date == _BASE + timedelta(days=39)
    assert a.observed_cost == 500.0
    assert a.direction == "SPIKE"
    assert a.z_score > 3.0
    assert a.severity in {"HIGH", "CRITICAL"}


def test_detect_anomalies_ignores_normal_variance() -> None:
    records = [
        _row(_BASE + timedelta(days=i), 100.0 + (2.0 if i % 2 == 0 else -2.0))
        for i in range(40)
    ]
    anomalies = detect_anomalies(records, z_threshold=3.0)
    assert anomalies == []


def test_detect_anomalies_empty_series() -> None:
    assert detect_anomalies([]) == []


def test_evaluate_anomalies_emits_findings() -> None:
    records = _stable_series_with_spike(spike_day=39, spike_cost=600.0)
    findings = evaluate_anomalies(
        records, subscription_id=SUB, tenant_id=TENANT
    )
    assert findings
    assert findings[0].rule_id == "FIN-AN-001"
    assert findings[0].finding_type.value == "FINOPS"
