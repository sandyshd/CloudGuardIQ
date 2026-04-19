"""CloudGuardIQ — Native scanner rule protocol and registry."""

from __future__ import annotations

import logging
from typing import Protocol

from cloudguardiq.core.models import FindingResult, ResourceSnapshot

logger = logging.getLogger(__name__)


class ScannerRule(Protocol):
    """Protocol for native scanner rules."""

    rule_id: str
    resource_types: list[str]

    def evaluate(self, snapshot: ResourceSnapshot) -> list[FindingResult]:
        """Evaluate a snapshot and return any findings."""
        ...


class NativeScanner:
    """Runs native scanner rules against ResourceSnapshots."""

    def __init__(self) -> None:
        self._rules: list[ScannerRule] = []

    def register(self, rule: ScannerRule) -> None:
        """Register a scanner rule."""
        self._rules.append(rule)

    def scan(self, snapshots: list[ResourceSnapshot]) -> list[FindingResult]:
        """Run all registered rules against the given snapshots."""
        findings: list[FindingResult] = []
        for snapshot in snapshots:
            for rule in self._rules:
                if snapshot.resource_type in rule.resource_types or "*" in rule.resource_types:
                    try:
                        results = rule.evaluate(snapshot)
                        findings.extend(results)
                    except Exception:
                        logger.exception(
                            "Rule %s failed on resource %s",
                            rule.rule_id,
                            snapshot.resource_id,
                        )
        return findings
