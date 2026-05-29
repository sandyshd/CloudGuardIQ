"""Industry-standard CSPM posture scoring.

Implements a *weighted control-pass* score in the style of Microsoft
Defender for Cloud Secure Score and AWS Security Hub:

    score = 100 * sum(weight_of_passed_rules) / sum(weight_of_all_rules)

* Each policy rule (control) carries a weight derived from its severity
  (CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFORMATIONAL=0).
* A rule is considered *failed* for the scope if at least one OPEN
  finding with that ``rule_id`` exists.
* The denominator is the full set of rules the engine actively
  evaluates, so the score is coverage-normalised (independent of tenant
  size) and severity-weighted (critical controls matter more than low).

This is the score surfaced as "Security Posture" on the dashboard.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from collections.abc import Iterable, Iterator

from pydantic import BaseModel

from cloudguardiq.core.enums import CloudProvider, FindingStatus, Severity
from cloudguardiq.core.models import FindingResult

logger = logging.getLogger(__name__)


def _iter_rule_classes() -> Iterator[type]:
    """Yield every class in ``cloudguardiq.adapters.rules`` exposing a
    ``rule_id``. Unlike the compliance scorecard iterator, this does not
    require ``compliance_frameworks`` so legacy rule classes are still
    counted toward the posture-score denominator.
    """
    pkg = importlib.import_module("cloudguardiq.adapters.rules")
    # Recursively walk provider subpackages (azure/, aws/, gcp/, ...)
    # so rules under cloudguardiq.adapters.rules.<provider>.* are seen.
    for mod_info in pkgutil.walk_packages(
        pkg.__path__, prefix=f"{pkg.__name__}.",
    ):
        short_name = mod_info.name.rsplit(".", 1)[-1]
        if short_name.startswith("_") or short_name == "base":
            continue
        try:
            module = importlib.import_module(mod_info.name)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Could not import rule module %s: %s", mod_info.name, exc)
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj.__module__ != module.__name__:
                continue
            rule_id = getattr(obj, "rule_id", None)
            if isinstance(rule_id, str) and rule_id:
                yield obj


def _rule_provider(cls: type) -> CloudProvider | None:
    """Infer the cloud provider for a rule class from its resource_types.

    Resource type strings follow each cloud's native naming convention:
    Azure uses ``Microsoft.<RP>/<Type>`` (e.g. ``Microsoft.Storage/storageAccounts``);
    AWS uses ``AWS::<Service>::<Type>``. Returns ``None`` when the rule
    has no resource_types declared or the prefix is unrecognized -- such
    rules are treated as provider-agnostic and always counted.
    """
    resource_types = getattr(cls, "resource_types", None)
    if not resource_types:
        return None
    for rt in resource_types:
        if not isinstance(rt, str):
            continue
        if rt.startswith("Microsoft."):
            return CloudProvider.AZURE
        if rt.startswith("AWS::"):
            return CloudProvider.AWS
        if rt.startswith("google."):
            return CloudProvider.GCP
    return None


SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}

_DEFAULT_WEIGHT = SEVERITY_WEIGHT[Severity.MEDIUM]


class PostureScore(BaseModel):
    """Single posture score response."""

    score: int
    grade: str
    rules_evaluated: int
    rules_passed: int
    rules_failed: int
    weighted_total: float
    weighted_passed: float
    methodology: str = "weighted-control-pass"


def _coerce_severity(value: object) -> Severity | None:
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        try:
            return Severity(value.upper())
        except ValueError:
            return None
    return None


def _rule_weight(cls: type) -> int:
    sev = _coerce_severity(getattr(cls, "severity", None))
    if sev is None:
        return _DEFAULT_WEIGHT
    return SEVERITY_WEIGHT.get(sev, _DEFAULT_WEIGHT)


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def compute_posture_score(
    findings: Iterable[FindingResult],
    *,
    providers: set[CloudProvider] | None = None,
) -> PostureScore:
    """Compute the weighted control-pass posture score.

    Args:
        findings: Findings for the requested scope (typically all findings
            for a subscription/tenant). Only OPEN findings reduce the
            score; RESOLVED / SNOOZED / APPLIED are ignored.

    Returns:
        A ``PostureScore`` with score (0-100), letter grade, and the
        underlying numerator/denominator for transparency.
    """
    rule_weights: dict[str, int] = {}
    for cls in _iter_rule_classes():
        rule_id = getattr(cls, "rule_id", None)
        if not isinstance(rule_id, str) or not rule_id:
            continue
        # When a provider filter is supplied (typically the providers
        # the caller has actually connected) skip rules tagged to a
        # different cloud so they do not artificially inflate the
        # denominator. Provider-agnostic rules (no resource_types)
        # always count.
        if providers is not None:
            rule_provider = _rule_provider(cls)
            if rule_provider is not None and rule_provider not in providers:
                continue
        rule_weights[rule_id] = _rule_weight(cls)

    total_weight = sum(rule_weights.values())
    if total_weight == 0:
        return PostureScore(
            score=100,
            grade="A",
            rules_evaluated=0,
            rules_passed=0,
            rules_failed=0,
            weighted_total=0.0,
            weighted_passed=0.0,
        )

    failing_rule_ids: set[str] = set()
    for f in findings:
        status = getattr(f, "status", None) or FindingStatus.OPEN
        if status != FindingStatus.OPEN:
            continue
        if f.rule_id in rule_weights:
            failing_rule_ids.add(f.rule_id)

    failed_weight = sum(rule_weights[r] for r in failing_rule_ids)
    passed_weight = total_weight - failed_weight
    score = round((passed_weight / total_weight) * 100)
    return PostureScore(
        score=score,
        grade=_grade(score),
        rules_evaluated=len(rule_weights),
        rules_passed=len(rule_weights) - len(failing_rule_ids),
        rules_failed=len(failing_rule_ids),
        weighted_total=float(total_weight),
        weighted_passed=float(passed_weight),
    )


__all__ = ["PostureScore", "compute_posture_score", "SEVERITY_WEIGHT"]

