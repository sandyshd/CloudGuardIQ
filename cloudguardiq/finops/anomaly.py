"""Statistical anomaly detection over FOCUS daily spend.

Pure functions, no cloud SDK. A trailing rolling mean/standard-deviation
baseline flags days whose spend deviates beyond a z-score threshold. Severity
scales with the magnitude of the deviation. ``evaluate_anomalies`` normalizes
spikes into FinOps findings.

A first-party cloud anomaly source (AWS Cost Anomaly Detection / Azure anomaly
alerts) can later be layered in as a DIRECT source behind the recommender
pattern without changing this baseline detector.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Iterable
from datetime import date

from pydantic import BaseModel

from cloudguardiq.core.enums import CloudProvider, Severity
from cloudguardiq.core.models import FindingResult, FocusCostRecord
from cloudguardiq.finops._common import build_finops_finding

DEFAULT_WINDOW_DAYS = 14
DEFAULT_MIN_PERIODS = 7
DEFAULT_Z_THRESHOLD = 3.0

RULE_ANOMALY = "FIN-AN-001"


class SpendAnomaly(BaseModel):
    """A single day whose spend deviates significantly from its baseline."""

    key: str
    date: date
    observed_cost: float
    baseline_mean: float
    baseline_stdev: float
    z_score: float
    direction: str  # "SPIKE" | "DROP"
    severity: str


def _daily_totals(records: Iterable[FocusCostRecord]) -> dict[date, float]:
    """Aggregate effective cost into per-day totals."""
    totals: dict[date, float] = defaultdict(float)
    for record in records:
        totals[record.charge_period_start.date()] += record.effective_cost
    return totals


def _severity_for(z_score: float) -> str:
    """Map an absolute z-score to a finding severity label."""
    z = abs(z_score)
    if z >= 5.0:
        return "CRITICAL"
    if z >= 4.0:
        return "HIGH"
    return "MEDIUM"


def detect_anomalies(
    records: Iterable[FocusCostRecord],
    *,
    key: str = "total",
    window: int = DEFAULT_WINDOW_DAYS,
    min_periods: int = DEFAULT_MIN_PERIODS,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
) -> list[SpendAnomaly]:
    """Return spend anomalies in the daily series, oldest first.

    For each day, a trailing window of up to ``window`` prior days forms the
    baseline. A day is flagged when at least ``min_periods`` prior days exist,
    the baseline has non-zero variance, and ``|z| >= z_threshold``.
    """
    totals = _daily_totals(records)
    if not totals:
        return []
    days = sorted(totals)
    anomalies: list[SpendAnomaly] = []
    for index, day in enumerate(days):
        window_days = days[max(0, index - window):index]
        if len(window_days) < min_periods:
            continue
        history = [totals[d] for d in window_days]
        mean = statistics.fmean(history)
        stdev = statistics.pstdev(history)
        if stdev <= 0:
            continue
        observed = totals[day]
        z_score = (observed - mean) / stdev
        if abs(z_score) < z_threshold:
            continue
        anomalies.append(
            SpendAnomaly(
                key=key,
                date=day,
                observed_cost=round(observed, 2),
                baseline_mean=round(mean, 2),
                baseline_stdev=round(stdev, 2),
                z_score=round(z_score, 2),
                direction="SPIKE" if z_score > 0 else "DROP",
                severity=_severity_for(z_score),
            )
        )
    return anomalies


def evaluate_anomalies(
    records: Iterable[FocusCostRecord],
    *,
    subscription_id: str = "",
    tenant_id: str = "",
    provider: CloudProvider = CloudProvider.AZURE,
    window: int = DEFAULT_WINDOW_DAYS,
    min_periods: int = DEFAULT_MIN_PERIODS,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
) -> list[FindingResult]:
    """Emit a FinOps finding per spend spike (drops are not cost risks)."""
    anomalies = detect_anomalies(
        records,
        window=window,
        min_periods=min_periods,
        z_threshold=z_threshold,
    )
    findings: list[FindingResult] = []
    for anomaly in anomalies:
        if anomaly.direction != "SPIKE":
            continue
        excess = max(anomaly.observed_cost - anomaly.baseline_mean, 0.0)
        findings.append(
            build_finops_finding(
                rule_id=RULE_ANOMALY,
                rule_name="Spend anomaly detected",
                provider=provider,
                subscription_id=subscription_id,
                tenant_id=tenant_id,
                resource_name=f"anomaly/{anomaly.key}/{anomaly.date.isoformat()}",
                description=(
                    f"Spend on {anomaly.date.isoformat()} was "
                    f"${anomaly.observed_cost:,.2f} vs a baseline of "
                    f"${anomaly.baseline_mean:,.2f} "
                    f"(z={anomaly.z_score})."
                ),
                evidence={
                    "date": anomaly.date.isoformat(),
                    "observed_cost": anomaly.observed_cost,
                    "baseline_mean": anomaly.baseline_mean,
                    "baseline_stdev": anomaly.baseline_stdev,
                    "z_score": anomaly.z_score,
                },
                estimated_impact_monthly_usd=excess,
                finops_method="ESTIMATED",
                finops_confidence="MEDIUM",
                severity=Severity(_severity_for(anomaly.z_score)),
            )
        )
    return findings
