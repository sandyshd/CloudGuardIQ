"""CloudGuardIQ — Policy engine that evaluates rules against ResourceSnapshots.

IMPORTANT: This module NEVER imports any Azure SDK. It operates solely on
ResourceSnapshot objects.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from cloudguardiq.core.enums import Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

logger = logging.getLogger(__name__)

# Type alias for a policy rule function
PolicyRule = Callable[[ResourceSnapshot], list[FindingResult]]


class PolicyEngine:
    """Evaluates registered policy rules against ResourceSnapshot objects."""

    def __init__(self) -> None:
        self._rules: list[PolicyRule] = []
        self._severity_filter: Severity | None = None

    def register_rule(self, rule: PolicyRule) -> None:
        """Register a policy evaluation rule."""
        self._rules.append(rule)

    def set_severity_filter(self, minimum: Severity) -> None:
        """Only return findings at or above this severity."""
        self._severity_filter = minimum

    def evaluate(self, snapshots: list[ResourceSnapshot]) -> list[FindingResult]:
        """Run all registered rules against the given snapshots."""
        all_findings: list[FindingResult] = []
        for snapshot in snapshots:
            for rule in self._rules:
                try:
                    findings = rule(snapshot)
                    all_findings.extend(findings)
                except Exception:
                    logger.exception(
                        "Policy rule failed on resource %s",
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
        return all_findings

    @property
    def rule_count(self) -> int:
        """Return the number of registered rules."""
        return len(self._rules)
