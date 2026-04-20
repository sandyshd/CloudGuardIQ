"""CloudGuardIQ -- Risk scoring for security and FinOps findings."""

from __future__ import annotations

from cloudguardiq.core.enums import Severity
from cloudguardiq.core.models import FindingResult

_SEVERITY_SCORES: dict[Severity, float] = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 80.0,
    Severity.MEDIUM: 60.0,
    Severity.LOW: 40.0,
    Severity.INFORMATIONAL: 20.0,
}


def compute_risk_score(
    finding: FindingResult,
    alpha: float = 0.5,
    beta: float = 0.3,
    gamma: float = 0.2,
) -> float:
    """Compute a composite risk score (0-100) for a finding.

    Formula:
        score = alpha * severity_score + beta * cost_normalised + gamma * compliance_count

    Where:
        - severity_score: CRITICAL=100, HIGH=80, MEDIUM=60, LOW=40, INFO=20
        - cost_normalised: min(waste_monthly_usd, 100.0)  (capped at 100)
        - compliance_count: min(len(compliance_frameworks) * 25.0, 100.0)

    Default weights: alpha=0.5, beta=0.3, gamma=0.2.

    Returns:
        A float between 0 and 100 (inclusive), rounded to 2 decimal places.
    """
    severity_score = _SEVERITY_SCORES.get(finding.severity, 0.0)
    cost_normalised = min(finding.waste_monthly_usd, 100.0)
    compliance_count = min(len(finding.compliance_frameworks) * 25.0, 100.0)

    score = alpha * severity_score + beta * cost_normalised + gamma * compliance_count
    return round(score, 2)
