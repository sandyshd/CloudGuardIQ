"""Audit-grade compliance scorecard.

For each supported framework we enumerate the controls referenced by the
policy rule registry (controls_total), count how many of those controls
have at least one OPEN finding for the requested scope (controls_failed),
and report ``score = controls_passed / controls_total * 100``.

The denominator is *the set of controls CloudGuardIQ actively evaluates*
-- not the published catalog size. This is the honest answer: of the
controls we evaluate, X% pass. The catalog-size denominator can be added
later as an "evaluation coverage" badge once each rule has been mapped
into the full published catalog for its framework.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from functools import lru_cache

from pydantic import BaseModel

from cloudguardiq.core.enums import FindingStatus, Severity
from cloudguardiq.core.models import FindingResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Framework catalogue
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FrameworkDef:
    """Canonical framework definition with the tag prefixes it owns."""

    id: str
    label: str
    short_label: str
    prefixes: tuple[str, ...]


# Order matters -- this is also the rendering order on the dashboard.
FRAMEWORKS: tuple[FrameworkDef, ...] = (
    FrameworkDef(
        id="CIS_AZURE",
        label="CIS Microsoft Azure Foundations Benchmark",
        short_label="CIS Azure",
        prefixes=("CIS_",),
    ),
    FrameworkDef(
        id="NIST_800_53",
        label="NIST SP 800-53 Rev. 5",
        short_label="NIST 800-53",
        prefixes=("NIST_",),
    ),
    FrameworkDef(
        id="ISO_27001",
        label="ISO/IEC 27001:2022",
        short_label="ISO 27001",
        prefixes=("ISO_27001_", "ISO27001_", "ISO_"),
    ),
    FrameworkDef(
        id="PCI_DSS",
        label="PCI DSS v4.0",
        short_label="PCI-DSS",
        prefixes=("PCI_DSS_", "PCI_", "PCIDSS_"),
    ),
    FrameworkDef(
        id="SOC2",
        label="SOC 2 Trust Services Criteria",
        short_label="SOC 2",
        prefixes=("SOC2_", "SOC_2_"),
    ),
)


_FRAMEWORK_BY_ID: dict[str, FrameworkDef] = {fw.id: fw for fw in FRAMEWORKS}


def _classify(tag: str) -> tuple[str, str] | None:
    """Return (framework_id, control_id) for a rule's compliance tag.

    Tags follow the convention ``{FRAMEWORK_PREFIX}{CONTROL_ID}`` e.g.
    ``CIS_3.1``, ``NIST_SC-28``, ``PCI_DSS_6.5.4``, ``SOC2_CC6.1``.
    Returns ``None`` for tags we cannot route to a known framework so
    they're surfaced in logs rather than silently miscounted.
    """
    if not tag:
        return None
    upper = tag.strip()
    for fw in FRAMEWORKS:
        for prefix in fw.prefixes:
            if upper.startswith(prefix):
                control = upper[len(prefix):]
                if control:
                    return fw.id, control
    return None


# ---------------------------------------------------------------------------
# Rule registry introspection
# ---------------------------------------------------------------------------


def _iter_rule_classes() -> Iterator[type]:
    """Yield every class in ``cloudguardiq.adapters.rules`` exposing both
    a ``rule_id`` and ``compliance_frameworks`` attribute.

    We deliberately avoid requiring inheritance from ``PolicyRule`` so the
    introspection picks up both the legacy ``@dataclass`` rules and the
    newer ``PolicyRule`` subclasses uniformly.
    """
    pkg = importlib.import_module("cloudguardiq.adapters.rules")
    for mod_info in pkgutil.iter_modules(pkg.__path__):
        if mod_info.name.startswith("_") or mod_info.name == "base":
            continue
        try:
            module = importlib.import_module(f"{pkg.__name__}.{mod_info.name}")
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Could not import rule module %s: %s", mod_info.name, exc)
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj.__module__ != module.__name__:
                continue
            rule_id = getattr(obj, "rule_id", None)
            frameworks = getattr(obj, "compliance_frameworks", None)
            if isinstance(rule_id, str) and isinstance(frameworks, (list, tuple)):
                yield obj


@lru_cache(maxsize=1)
def _build_catalogue() -> dict[str, set[str]]:
    """Return ``{framework_id: {control_id, ...}}`` covering every control
    referenced by any rule in the registry. Cached for the process lifetime;
    rules are static so re-scanning is wasteful."""
    catalogue: dict[str, set[str]] = {fw.id: set() for fw in FRAMEWORKS}
    unknown: set[str] = set()
    for cls in _iter_rule_classes():
        for tag in getattr(cls, "compliance_frameworks", []) or []:
            classified = _classify(tag)
            if classified is None:
                unknown.add(tag)
                continue
            framework_id, control_id = classified
            catalogue[framework_id].add(control_id)
    if unknown:
        logger.info(
            "Compliance scorecard ignored %d tag(s) with unknown framework prefix: %s",
            len(unknown),
            sorted(unknown),
        )
    return catalogue


def reset_catalogue_cache() -> None:
    """Drop the cached catalogue. Intended for tests."""
    _build_catalogue.cache_clear()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class FrameworkScore(BaseModel):
    """Per-framework score row for the API response."""

    framework_id: str
    label: str
    short_label: str
    controls_total: int
    controls_failed: int
    controls_passed: int
    score: int
    open_findings: int
    severity_breakdown: SeverityBreakdown


# Statuses that explicitly take a finding out of the OPEN bucket. Anything
# else (including unexpected casing or missing field) is treated as OPEN so
# legacy rows never silently disappear from the scorecard.
_CLOSED_STATUSES: frozenset[FindingStatus] = frozenset({
    FindingStatus.RESOLVED,
    FindingStatus.SNOOZED,
    FindingStatus.APPLIED,
})

def compute_scorecard(findings: Iterable[FindingResult]) -> list[FrameworkScore]:
    """Compute the scorecard for an iterable of findings.

    Only ``OPEN`` findings (or findings with no explicit status, which the
    backend treats as open) contribute to ``controls_failed``. Resolved,
    snoozed, and applied findings are excluded.
    """
    catalogue = _build_catalogue()

    failed_controls: dict[str, set[str]] = {fw.id: set() for fw in FRAMEWORKS}
    open_finding_counts: dict[str, int] = {fw.id: 0 for fw in FRAMEWORKS}
    severity_counts: dict[str, dict[str, int]] = {
        fw.id: {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for fw in FRAMEWORKS
    }

    # Treat anything not explicitly closed as OPEN -- see _CLOSED_STATUSES
    # at module scope. Mirrors the same lenient rule used by the dashboard.
    for f in findings:
        raw = getattr(f, "status", None)
        if raw is None:
            normalised = FindingStatus.OPEN
        elif isinstance(raw, FindingStatus):
            normalised = raw
        else:
            try:
                normalised = FindingStatus(str(raw).upper())
            except ValueError:
                normalised = FindingStatus.OPEN
        if normalised in _CLOSED_STATUSES:
            continue
        sev = f.severity
        for tag in f.compliance_frameworks or []:
            classified = _classify(tag)
            if classified is None:
                continue
            framework_id, control_id = classified
            failed_controls[framework_id].add(control_id)
            open_finding_counts[framework_id] += 1
            if sev == Severity.CRITICAL:
                severity_counts[framework_id]["critical"] += 1
            elif sev == Severity.HIGH:
                severity_counts[framework_id]["high"] += 1
            elif sev == Severity.MEDIUM:
                severity_counts[framework_id]["medium"] += 1
            elif sev == Severity.LOW:
                severity_counts[framework_id]["low"] += 1

    rows: list[FrameworkScore] = []
    for fw in FRAMEWORKS:
        total = len(catalogue[fw.id])
        failed = len(failed_controls[fw.id])
        # When the registry has zero controls for a framework we still
        # return a row so the UI can render a "Not yet evaluated" tile
        # instead of silently dropping it.
        if total == 0:
            score = 100
            passed = 0
        else:
            failed = min(failed, total)
            passed = total - failed
            score = round((passed / total) * 100)
        rows.append(
            FrameworkScore(
                framework_id=fw.id,
                label=fw.label,
                short_label=fw.short_label,
                controls_total=total,
                controls_failed=failed,
                controls_passed=passed,
                score=score,
                open_findings=open_finding_counts[fw.id],
                severity_breakdown=SeverityBreakdown(
                    critical=severity_counts[fw.id]["critical"],
                    high=severity_counts[fw.id]["high"],
                    medium=severity_counts[fw.id]["medium"],
                    low=severity_counts[fw.id]["low"],
                ),
            )
        )
    return rows


__all__ = [
    "FRAMEWORKS",
    "FrameworkDef",
    "FrameworkScore",
    "SeverityBreakdown",
    "compute_scorecard",
    "reset_catalogue_cache",
]
