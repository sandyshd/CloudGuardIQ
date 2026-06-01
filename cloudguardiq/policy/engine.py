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

from cloudguardiq.core.enums import DataTier, FindingType, Severity
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



def _effective_monthly_impact(finding: FindingResult) -> float:
    """Return the strongest monthly cost impact signal on a finding."""
    return max(
        finding.waste_monthly_usd,
        finding.direct_waste_monthly_usd,
        finding.estimated_impact_monthly_usd,
        0.0,
    )


def _estimate_monthly_impact(finding: FindingResult) -> float:
    """Estimate monthly cost impact for findings without direct waste."""
    snapshot = finding.resource_snapshot
    if snapshot is None:
        return 0.0

    default_cost_by_type: dict[str, float] = {
        "microsoft.compute/virtualmachines": 120.0,
        "microsoft.compute/disks": 30.0,
        "microsoft.network/publicipaddresses": 12.0,
        "microsoft.keyvault/vaults": 20.0,
        "microsoft.storage/storageaccounts": 25.0,
        "microsoft.network/networksecuritygroups": 8.0,
    }

    observed_cost = max(float(snapshot.cost_monthly), 0.0)
    if observed_cost > 0.0:
        base_cost = observed_cost
    else:
        resource_type = snapshot.resource_type.lower()
        base_cost = 0.0
        for prefix, fallback in default_cost_by_type.items():
            if resource_type.startswith(prefix):
                base_cost = fallback
                break

    if base_cost <= 0.0:
        return 0.0

    base_factor_by_type: dict[FindingType, float] = {
        FindingType.SECURITY: 0.15,
        FindingType.COMPLIANCE: 0.10,
        FindingType.FINOPS: 0.08,
    }
    severity_factor: dict[Severity, float] = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.75,
        Severity.MEDIUM: 0.5,
        Severity.LOW: 0.25,
        Severity.INFORMATIONAL: 0.1,
    }
    tier_factor: dict[DataTier, float] = {
        DataTier.TIER1_NATIVE: 1.0,
        DataTier.TIER2_FREE_CSPM: 1.05,
        DataTier.TIER2_ENRICHED: 1.05,
        DataTier.TIER3_PAID: 1.1,
        DataTier.TIER3_DEEP: 1.1,
    }

    base_factor = base_factor_by_type.get(finding.finding_type, 0.0)
    sev_factor = severity_factor.get(finding.severity, 0.0)
    data_tier_factor = tier_factor.get(snapshot.data_tier, 1.0)

    estimated = round(base_cost * base_factor * sev_factor * data_tier_factor, 2)
    return min(estimated, round(base_cost, 2))

def _enrich_finops_impact(findings: list[FindingResult]) -> None:
    """Populate direct and estimated monthly impact fields on findings."""
    for finding in findings:
        direct = max(
            finding.direct_waste_monthly_usd,
            finding.waste_monthly_usd,
            0.0,
        )
        finding.direct_waste_monthly_usd = round(direct, 2)

        if finding.direct_waste_monthly_usd > 0.0:
            finding.waste_monthly_usd = finding.direct_waste_monthly_usd
            finding.estimated_impact_monthly_usd = 0.0
            finding.finops_method = "DIRECT"
            finding.finops_confidence = "HIGH"
            continue

        estimated = _estimate_monthly_impact(finding)
        finding.estimated_impact_monthly_usd = estimated
        if estimated > 0.0:
            finding.finops_method = "ESTIMATED"
            if finding.resource_snapshot and finding.resource_snapshot.cost_monthly <= 0.0:
                finding.finops_confidence = "LOW"
            else:
                finding.finops_confidence = "MEDIUM"
        else:
            finding.finops_method = "NONE"
            finding.finops_confidence = "LOW"

def _compute_priority(finding: FindingResult) -> float:
    """Compute priority_score for a FindingResult.

    Formula: 0.5 * severity + 0.3 * cost + 0.2 * compliance
    """
    alpha, beta, gamma = 0.5, 0.3, 0.2
    score = round(
        alpha * _severity_weight(finding.severity)
        + beta * _cost_weight(_effective_monthly_impact(finding))
        + gamma * _compliance_weight(len(finding.compliance_frameworks)),
        2,
    )
    finding.priority_score = score
    return score


def _discover_rules() -> list[Any]:
    """Auto-discover and instantiate every PolicyRule subclass.

    Recursively walks ``cloudguardiq.adapters.rules`` (including provider
    subpackages such as ``aws/``) and instantiates every concrete
    ``PolicyRule`` subclass it finds. Duplicates by ``rule_id`` are
    de-duplicated so a class re-exported from a registry module is only
    registered once.
    """
    from cloudguardiq.adapters.rules.base import PolicyRule as PolicyRuleBase

    rules: list[Any] = []
    seen_ids: set[str] = set()
    package = importlib.import_module("cloudguardiq.adapters.rules")
    for _finder, module_name, _ispkg in pkgutil.walk_packages(
        package.__path__, prefix="cloudguardiq.adapters.rules."
    ):
        if module_name.endswith(".base"):
            continue
        try:
            mod = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to import rule module %s: %s", module_name, exc)
            continue
        for _name, obj in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(obj, PolicyRuleBase)
                and obj is not PolicyRuleBase
                and not inspect.isabstract(obj)
            ):
                rule_id = getattr(obj, "rule_id", None)
                if rule_id and rule_id in seen_ids:
                    continue
                rules.append(obj())
                if rule_id:
                    seen_ids.add(rule_id)
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
                rule_types = getattr(rule_obj, "resource_types", None)
                if rule_types and snapshot.resource_type not in rule_types:
                    # Rule declares a type whitelist that excludes this
                    # snapshot. Skip -- this is the cross-cloud routing
                    # guarantee: AWS rules never see Azure snapshots.
                    continue
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

        # Deduplicate by stable finding_id. A rule registered twice (or a
        # legacy/registry rule overlap) yields identical finding_ids; Cosmos
        # upserts on finding_id, so the persisted count would otherwise be
        # lower than the response count, shrinking the dashboard after a
        # refresh. Collapse duplicates here so the canonical result matches
        # what is stored.
        deduped: dict[str, FindingResult] = {}
        for f in all_findings:
            deduped.setdefault(f.finding_id, f)
        all_findings = list(deduped.values())

        # Compute priority scores and sort descending
        _enrich_finops_impact(all_findings)
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

        # Deduplicate by stable finding_id. A rule registered twice (or a
        # legacy/registry rule overlap) yields identical finding_ids; Cosmos
        # upserts on finding_id, so the persisted count would otherwise be
        # lower than the response count, shrinking the dashboard after a
        # refresh. Collapse duplicates here so the canonical result matches
        # what is stored.
        deduped: dict[str, FindingResult] = {}
        for f in all_findings:
            deduped.setdefault(f.finding_id, f)
        all_findings = list(deduped.values())

        # Compute priority scores and sort descending
        _enrich_finops_impact(all_findings)
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
            rule_types = getattr(rule_obj, "resource_types", None)
            if rule_types and snapshot.resource_type not in rule_types:
                continue
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









