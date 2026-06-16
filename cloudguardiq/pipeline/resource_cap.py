"""CloudGuardIQ -- tier-aware inventory resource cap.

Bounds the number of :class:`ResourceSnapshot` objects retained per scan based
on the tenant's plan tier. ``cloudguardiq.billing.plans`` is the single source
of truth for the per-tier ``max_resources_per_scan`` limit -- this module never
hard-codes tier numbers.

When discovered inventory exceeds the tier cap, snapshots are ordered so the
highest-value resources survive truncation: those covered by a native policy
rule rank above uncovered resources, and within each group higher monthly cost
ranks first. The sort is stable, so for otherwise-equal resources the original
discovery order is preserved.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable

from cloudguardiq.billing.plans import is_unlimited
from cloudguardiq.core.models import ResourceSnapshot

logger = logging.getLogger(__name__)


def _value_sort_key(
    covered_types: frozenset[str],
) -> Callable[[ResourceSnapshot], tuple[bool, float]]:
    """Return a sort key favouring rule-covered, then costlier, resources."""

    def key(snapshot: ResourceSnapshot) -> tuple[bool, float]:
        is_covered = snapshot.resource_type.lower() in covered_types
        return (is_covered, snapshot.cost_monthly)

    return key


def cap_snapshots(
    snapshots: list[ResourceSnapshot],
    max_resources: int,
    *,
    covered_types: Iterable[str] = (),
    tenant_id: str = "",
    tier: str = "",
) -> tuple[list[ResourceSnapshot], int]:
    """Truncate *snapshots* to *max_resources*, keeping highest-value first.

    Args:
        snapshots: Discovered resource snapshots from the adapter scan.
        max_resources: The tier's ``max_resources_per_scan``. ``UNLIMITED``
            (``-1``) means no cap.
        covered_types: Resource-type strings that have at least one native
            policy rule; membership boosts a snapshot's retention priority.
            Compared case-insensitively.
        tenant_id: Tenant identifier, included in the truncation log.
        tier: Plan tier name, included in the truncation log.

    Returns:
        A ``(kept, dropped)`` tuple. When no truncation is required the original
        list is returned unchanged with ``dropped == 0``.
    """
    total = len(snapshots)
    if is_unlimited(max_resources) or total <= max_resources:
        return snapshots, 0

    normalized = frozenset(str(t).lower() for t in covered_types)
    ordered = sorted(snapshots, key=_value_sort_key(normalized), reverse=True)
    kept = ordered[:max_resources]
    dropped = total - len(kept)

    logger.warning(
        "Resource cap applied: tenant=%s tier=%s cap=%d total_discovered=%d "
        "dropped=%d",
        tenant_id or "<unknown>",
        tier or "<unknown>",
        max_resources,
        total,
        dropped,
        extra={
            "event": "resource_cap_truncation",
            "tenant_id": tenant_id or "<unknown>",
            "tier": tier or "<unknown>",
            "cap": max_resources,
            "total_discovered": total,
            "dropped": dropped,
        },
    )
    return kept, dropped
