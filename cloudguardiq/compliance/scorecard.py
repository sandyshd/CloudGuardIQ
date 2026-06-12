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

from cloudguardiq.core.enums import CloudProvider, FindingStatus, Severity
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
    FrameworkDef(
        id="HIPAA",
        label="HIPAA Security Rule (45 CFR §164)",
        short_label="HIPAA",
        prefixes=("HIPAA_",),
    ),
)


_FRAMEWORK_BY_ID: dict[str, FrameworkDef] = {fw.id: fw for fw in FRAMEWORKS}


def _classify(tag: str) -> tuple[str, str] | None:
    """Return (framework_id, control_id) for a rule's compliance tag.

    Tags follow either the prefix convention ``{FRAMEWORK_PREFIX}{CONTROL_ID}``
    (e.g. ``CIS_3.1``, ``NIST_SC-28``, ``SOC2_CC6.1``) or the explicit
    ``{FRAMEWORK_ID}:{CONTROL_ID}`` form emitted by the Azure Policy adapter
    (e.g. ``CIS_AZURE:3.1``, ``SOC2:CC6.1``).
    Returns ``None`` for tags we cannot route to a known framework so
    they're surfaced in logs rather than silently miscounted.
    """
    if not tag:
        return None
    upper = tag.strip()
    # Explicit ``{FRAMEWORK_ID}:{CONTROL_ID}`` form (Azure Policy adapter).
    if ":" in upper:
        fw_id, _, control = upper.partition(":")
        if fw_id in _FRAMEWORK_BY_ID and control:
            return fw_id, control
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
    # Recursively walk every provider subpackage (azure/, aws/, gcp/, ...)
    # so rule classes living under cloudguardiq.adapters.rules.<provider>.*
    # are picked up alongside any flat modules.
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
            frameworks = getattr(obj, "compliance_frameworks", None)
            if isinstance(rule_id, str) and isinstance(frameworks, (list, tuple)):
                yield obj


def _rule_provider(cls: type) -> CloudProvider | None:
    """Infer the cloud provider for a rule class from its resource_types.

    Azure: ``Microsoft.<RP>/<Type>`` -> AZURE
    AWS:   ``AWS::<Service>::<Type>`` -> AWS
    GCP:   ``google.<service>.<Type>`` -> GCP
    Anything else (or no resource_types) -> None, treated as
    provider-agnostic and always counted.
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


@lru_cache(maxsize=8)
def _build_catalogue(
    providers_key: frozenset[CloudProvider] | None = None,
) -> dict[str, set[str]]:
    """Return ``{framework_id: {control_id, ...}}`` covering every control
    referenced by any rule in the registry. Cached per-providers key so
    repeated calls with the same scope avoid re-scanning rule modules.

    When ``providers_key`` is None the catalogue includes every rule
    (legacy behavior). When set, only rules whose ``_rule_provider``
    is in the set (or None / provider-agnostic) are counted, so the
    score is not diluted by rule packs for clouds the caller has not
    connected.
    """
    catalogue: dict[str, set[str]] = {fw.id: set() for fw in FRAMEWORKS}
    unknown: set[str] = set()
    for cls in _iter_rule_classes():
        if providers_key is not None:
            rp = _rule_provider(cls)
            if rp is not None and rp not in providers_key:
                continue
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
    # Tag prefixes the backend uses to route a finding's
    # ``compliance_frameworks`` tag to this row (e.g. ``CIS_AZURE``'s
    # prefixes are ``("CIS_",)``). Shipped so the frontend can filter
    # findings by family without duplicating the prefix table.
    prefixes: tuple[str, ...] = ()
    controls_total: int
    controls_failed: int
    controls_passed: int
    score: int
    open_findings: int
    severity_breakdown: SeverityBreakdown


def compute_scorecard(
    findings: Iterable[FindingResult],
    *,
    providers: set[CloudProvider] | None = None,
) -> list[FrameworkScore]:
    """Compute the scorecard for an iterable of findings.

    Only ``OPEN`` findings (or findings with no explicit status, which the
    backend treats as open) contribute to ``controls_failed``. Resolved,
    snoozed, and applied findings are excluded.
    """
    providers_key = frozenset(providers) if providers else None
    catalogue = _build_catalogue(providers_key)

    failed_controls: dict[str, set[str]] = {fw.id: set() for fw in FRAMEWORKS}
    open_finding_counts: dict[str, int] = {fw.id: 0 for fw in FRAMEWORKS}
    severity_counts: dict[str, dict[str, int]] = {
        fw.id: {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for fw in FRAMEWORKS
    }

    for f in findings:
        # Treat missing status as OPEN to mirror the rest of the codebase.
        status = getattr(f, "status", None) or FindingStatus.OPEN
        if status != FindingStatus.OPEN:
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
                prefixes=fw.prefixes,
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
