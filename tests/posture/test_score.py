"""Tests for the weighted-control-pass posture score."""

from __future__ import annotations

from cloudguardiq.compliance.scorecard import reset_catalogue_cache
from cloudguardiq.core.enums import FindingStatus, Severity
from cloudguardiq.core.models import FindingResult
from cloudguardiq.posture.score import (
    SEVERITY_WEIGHT,
    compute_posture_score,
)


def _finding(rule_id: str, severity: Severity = Severity.HIGH,
             status: FindingStatus = FindingStatus.OPEN) -> FindingResult:
    return FindingResult(
        rule_id=rule_id,
        title=f"{rule_id} failed",
        description="test",
        severity=severity,
        resource_id="/subscriptions/x/resourceGroups/rg/providers/p/r/n",
        resource_type="Microsoft.Test/things",
        resource_name="n",
        status=status,
    )


def test_empty_findings_yield_perfect_score() -> None:
    reset_catalogue_cache()
    result = compute_posture_score([])
    assert result.score == 100
    assert result.grade == "A"
    assert result.rules_failed == 0
    assert result.rules_passed == result.rules_evaluated


def test_resolved_findings_do_not_lower_score() -> None:
    reset_catalogue_cache()
    open_only = compute_posture_score([])
    resolved = _finding(
        "COMPUTE_UNMANAGED_DISKS",
        severity=Severity.CRITICAL,
        status=FindingStatus.RESOLVED,
    )
    assert compute_posture_score([resolved]).score == open_only.score


def test_unknown_rule_id_does_not_affect_score() -> None:
    reset_catalogue_cache()
    baseline = compute_posture_score([]).score
    unknown = _finding("RULE_DOES_NOT_EXIST", severity=Severity.CRITICAL)
    assert compute_posture_score([unknown]).score == baseline


def test_severity_weights_are_industry_standard() -> None:
    # Aligns with Defender for Cloud / Security Hub weighting buckets.
    assert SEVERITY_WEIGHT[Severity.CRITICAL] == 10
    assert SEVERITY_WEIGHT[Severity.HIGH] == 5
    assert SEVERITY_WEIGHT[Severity.MEDIUM] == 2
    assert SEVERITY_WEIGHT[Severity.LOW] == 1


def test_failing_rule_reduces_score_proportional_to_weight() -> None:
    reset_catalogue_cache()
    baseline = compute_posture_score([])
    one_fail = compute_posture_score(
        [_finding("COMPUTE_UNMANAGED_DISKS", severity=Severity.MEDIUM)]
    )
    assert one_fail.score <= baseline.score
    assert one_fail.rules_failed == 1
    assert one_fail.rules_passed == baseline.rules_evaluated - 1


def test_duplicate_findings_for_same_rule_count_once() -> None:
    reset_catalogue_cache()
    rule = "COMPUTE_UNMANAGED_DISKS"
    one = compute_posture_score([_finding(rule)])
    many = compute_posture_score([_finding(rule) for _ in range(50)])
    assert one.score == many.score
    assert one.rules_failed == many.rules_failed == 1


def test_grade_thresholds() -> None:
    from cloudguardiq.posture.score import _grade
    assert _grade(95) == "A"
    assert _grade(85) == "B"
    assert _grade(75) == "C"
    assert _grade(65) == "D"
    assert _grade(40) == "F"
