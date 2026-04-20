"""CloudGuardIQ -- Policy engine that evaluates rules against ResourceSnapshots.

IMPORTANT: This module NEVER imports any Azure SDK. It operates solely on
ResourceSnapshot objects.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import pkgutil
from collections.abc import Callable
from typing import Any

from cloudguardiq.core.enums import Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

logger = logging.getLogger(__name__)

# Type alias for a legacy policy rule function
PolicyRuleCallable = Callable[[ResourceSnapshot], list[FindingResult]]

# Keep backward-compatible alias
PolicyRule = PolicyRuleCallable

# Severity weights for priority scoring
_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 75.0,
    Severity.MEDIUM: 50.0,
    Severity.LOW: 25.0,
    Severity.INFORMATIONAL: 10.0,
}


def _severity_weight(severity: Severity) -> float:
    """Return the severity weight for priority scoring."""
    return _SEVERITY_WEIGHT.get(severity, 0.0)


def _cost_weight(waste_monthly_usd: float) -> float:
    """Return the cost weight for priority scoring (max 100)."""
    return min(100.0, waste_monthly_usd / 10.0)


def _compliance_weight(framework_count: int) -> float:
    """Return the compliance weight for priority scoring (max 100)."""
    return min(100.0, framework_count * 25.0)


def _compute_priority(finding: FindingResult) -> float:
    """Compute priority_score for a FindingResult.

    Formula: 0.5 * severity + 0.3 * cost + 0.2 * compliance
    """
    alpha, beta, gamma = 0.5, 0.3, 0.2
    score = round(
        alpha * _severity_weight(finding.severity)
        + beta * _cost_weight(finding.waste_monthly_usd)
        + gamma * _compliance_weight(len(finding.compliance_frameworks)),
        2,
    )
    finding.priority_score = score
    return score


def _discover_rules() -> list[Any]:
    """Auto-discover and instantiate all PolicyRule subclasses from adapters/rules/.

    Scans all modules under `cloudguardiq.adapters.rules` for classes that
    inherit from `cloudguardiq.adapters.rules.base.PolicyRule`.
    """
    from cloudguardiq.adapters.rules.base import PolicyRule as PolicyRuleBase

    rules: list[Any] = []
    package = importlib.import_module("cloudguardiq.adapters.rules")
    for _importer, module_name, _ispkg in pkgutil.iter_modules(package.__path__):
        if module_name == "base":
            continue
        full_name = f"cloudguardiq.adapters.rules.{module_name}"
        mod = importlib.import_module(full_name)
        for _name, obj in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(obj, PolicyRuleBase)
                and obj is not PolicyRuleBase
                and not inspect.isabstract(obj)
            ):
                rules.append(obj())
    return rules


class PolicyEngine:
    """Evaluates registered policy rules against ResourceSnapshot objects."""

    def __init__(self, rules: list[Any] | None = None) -> None:
        self._rules: list[PolicyRuleCallable] = []
        self._native_rules: list[Any] = []
        self._severity_filter: Severity | None = None

        if rules is not None:
            self._native_rules = list(rules)
        else:
            self._native_rules = _discover_rules()

    # ------------------------------------------------------------------
    # Legacy sync API (backward compatible)
    # ------------------------------------------------------------------

    def register_rule(self, rule: PolicyRuleCallable) -> None:
        """Register a legacy policy evaluation rule (callable)."""
        self._rules.append(rule)

    def set_severity_filter(self, minimum: Severity) -> None:
        """Only return findings at or above this severity."""
        self._severity_filter = minimum

    def evaluate(self, snapshots: list[ResourceSnapshot]) -> list[FindingResult]:
        """Run all registered rules against the given snapshots (sync)."""
        all_findings: list[FindingResult] = []
        for snapshot in snapshots:
            # Run legacy callable rules
            for rule in self._rules:
                try:
                    findings = rule(snapshot)
                    all_findings.extend(findings)
                except Exception:
                    logger.exception(
                        "Policy rule failed on resource %s",
                        snapshot.resource_id,
                    )
            # Run native PolicyRule instances
            for rule_obj in self._native_rules:
                try:
                    result = rule_obj.evaluate(snapshot)
                    if result is not None:
                        if isinstance(result, list):
                            all_findings.extend(result)
                        else:
                            all_findings.append(result)
                except Exception:
                    logger.exception(
                        "Native rule %s failed on resource %s",
                        getattr(rule_obj, "rule_id", "unknown"),
                        snapshot.resource_id,
                    )

        if self._severity_filter:
            severity_order = list(Severity)
            min_idx = severity_order.index(self._severity_filter)
            all_findings = [
                f
                for f in all_findings
                if severity_order.index(f.severity) <= min_idx
            ]

        # Compute priority scores and sort descending
        for f in all_findings:
            _compute_priority(f)
        all_findings.sort(key=lambda f: f.priority_score, reverse=True)

        return all_findings

    # ------------------------------------------------------------------
    # Async API
    # ------------------------------------------------------------------

    async def evaluate_async(
        self, snapshots: list[ResourceSnapshot],
    ) -> list[FindingResult]:
        """Run all rules against all snapshots in parallel.

        Uses asyncio.gather() for parallelism.
        Returns only non-None FindingResult objects (failing checks only).
        """
        if not snapshots:
            return []

        tasks = [self.evaluate_single(snap) for snap in snapshots]
        results = await asyncio.gather(*tasks)

        all_findings: list[FindingResult] = []
        for findings in results:
            all_findings.extend(findings)

        if self._severity_filter:
            severity_order = list(Severity)
            min_idx = severity_order.index(self._severity_filter)
            all_findings = [
                f
                for f in all_findings
                if severity_order.index(f.severity) <= min_idx
            ]

        # Compute priority scores and sort descending
        for f in all_findings:
            _compute_priority(f)
        all_findings.sort(key=lambda f: f.priority_score, reverse=True)

        return all_findings

    async def evaluate_single(
        self, snapshot: ResourceSnapshot,
    ) -> list[FindingResult]:
        """Run all rules against a single snapshot."""
        findings: list[FindingResult] = []

        # Legacy callable rules
        for rule in self._rules:
            try:
                result = rule(snapshot)
                findings.extend(result)
            except Exception:
                logger.exception(
                    "Policy rule failed on resource %s",
                    snapshot.resource_id,
                )

        # Native PolicyRule instances
        for rule_obj in self._native_rules:
            try:
                result = rule_obj.evaluate(snapshot)
                if result is not None:
                    if isinstance(result, list):
                        findings.extend(result)
                    else:
                        findings.append(result)
            except Exception:
                logger.exception(
                    "Native rule %s failed on resource %s",
                    getattr(rule_obj, "rule_id", "unknown"),
                    snapshot.resource_id,
                )

        return findings

    def get_rules_for_resource_type(self, resource_type: str) -> list[Any]:
        """Return only rules applicable to a given resource type."""
        matching: list[Any] = []
        for rule_obj in self._native_rules:
            resource_types = getattr(rule_obj, "resource_types", None)
            if resource_types is None or resource_type in resource_types:
                matching.append(rule_obj)
        return matching

    @property
    def rule_count(self) -> int:
        """Return the number of registered rules."""
        return len(self._rules) + len(self._native_rules)

    @property
    def native_rule_count(self) -> int:
        """Return the number of auto-discovered native rules."""
        return len(self._native_rules)
