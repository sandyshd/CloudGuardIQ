"""CloudGuardIQ -- provider-agnostic utilization metrics seam.

Parallel to :mod:`cloudguardiq.billing.cost_provider`. A
:class:`MetricsProvider` returns P95-based CPU/memory utilization for a batch
of resources so the scanner can stamp ``avg_cpu_7d`` / ``avg_memory_7d`` into
``ResourceSnapshot.config`` *before* policy evaluation -- activating the
idle/rightsizing FinOps rules without any change to the policy engine.

Design notes
------------
* **P95, not mean**, is used for the rightsizing signal so a few idle troughs
  do not mask sustained load (and a few spikes do not block a clear idle call).
* This module imports **no cloud SDK**; concrete providers (Azure Monitor,
  CloudWatch, Cloud Monitoring) live in their own modules and are injected
  behind this interface. Rule modules may import the lightweight helpers here
  (thresholds, observation guard) with no SDK dependency.
* Every public call is graceful: a metrics failure yields ``{}`` so a resource
  simply keeps no metric keys and the corresponding rule stays dormant.
"""

from __future__ import annotations

import abc
import logging
import math
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

logger = logging.getLogger(__name__)

# FinOps-standard observation window for rightsizing/idle analysis.
DEFAULT_WINDOW_DAYS = 14

# Minimum observation guard: short-lived / batch workloads must not be flagged
# idle or oversized on a sliver of data. A rule only fires when the resource
# has been observed for at least this many days with at least this many samples
# (Azure/AWS poll hourly -> 24 samples == one full day).
MIN_OBSERVATION_DAYS = 7
MIN_SAMPLE_COUNT = 24


class ResourceUtilization(BaseModel):
    """Normalized utilization summary for a single resource over a window."""

    model_config = ConfigDict(frozen=True)

    avg_cpu: float | None = None
    p95_cpu: float | None = None
    avg_mem: float | None = None
    p95_mem: float | None = None
    observation_days: int = 0
    sample_count: int = 0


def percentile(values: Sequence[float], pct: float) -> float | None:
    """Return the *pct* percentile of *values* via linear interpolation.

    ``pct`` is in ``[0, 100]``. Returns ``None`` for an empty sequence.
    """
    data = sorted(float(v) for v in values if v is not None)
    if not data:
        return None
    if len(data) == 1:
        return data[0]
    rank = (pct / 100.0) * (len(data) - 1)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return data[low]
    return data[low] + (data[high] - data[low]) * (rank - low)


def _span_days(timestamps: Sequence[Any]) -> int:
    """Return the inclusive calendar-day span covered by *timestamps*."""
    stamps = [t for t in timestamps if isinstance(t, datetime)]
    if not stamps:
        return 0
    return max(1, (max(stamps) - min(stamps)).days + 1)


def build_utilization(
    cpu_values: Sequence[float] | None = None,
    cpu_timestamps: Sequence[Any] | None = None,
    mem_values: Sequence[float] | None = None,
    mem_timestamps: Sequence[Any] | None = None,
) -> ResourceUtilization | None:
    """Summarize raw metric samples into a :class:`ResourceUtilization`.

    Computes mean and P95 for CPU and memory series and derives the
    observation window from sample timestamps (falling back to an hourly
    cadence assumption when timestamps are absent). Returns ``None`` when no
    usable samples were supplied so the caller stamps nothing.
    """
    cpu = [float(v) for v in (cpu_values or []) if v is not None]
    mem = [float(v) for v in (mem_values or []) if v is not None]
    if not cpu and not mem:
        return None

    sample_count = max(len(cpu), len(mem))
    observation_days = _span_days(list(cpu_timestamps or []) + list(mem_timestamps or []))
    if observation_days == 0 and sample_count:
        # No timestamps -> assume hourly samples (24/day).
        observation_days = max(1, round(sample_count / 24))

    return ResourceUtilization(
        avg_cpu=(sum(cpu) / len(cpu)) if cpu else None,
        p95_cpu=percentile(cpu, 95) if cpu else None,
        avg_mem=(sum(mem) / len(mem)) if mem else None,
        p95_mem=percentile(mem, 95) if mem else None,
        observation_days=observation_days,
        sample_count=sample_count,
    )


def is_observation_sufficient(config: dict[str, Any]) -> bool:
    """Return ``True`` when stamped metric coverage clears the minimum guard.

    Reads ``metric_sample_count`` / ``metric_observation_days`` from a snapshot
    config. Missing keys -> insufficient (so a rule never fires on a resource
    whose utilization was never measured).
    """
    samples = config.get("metric_sample_count")
    days = config.get("metric_observation_days")
    if not isinstance(samples, (int, float)) or not isinstance(days, (int, float)):
        return False
    return samples >= MIN_SAMPLE_COUNT and days >= MIN_OBSERVATION_DAYS


class MetricsProvider(abc.ABC):
    """Provider-agnostic utilization source consumed during a scan."""

    @abc.abstractmethod
    async def _fetch_utilization(
        self, resource_ids: Sequence[str], window_days: int
    ) -> dict[str, ResourceUtilization]:
        """Fetch utilization for *resource_ids*. Errors here are caught above."""

    async def get_utilization(
        self,
        resource_ids: Sequence[str],
        window_days: int = DEFAULT_WINDOW_DAYS,
    ) -> dict[str, ResourceUtilization]:
        """Return utilization keyed by lower-cased resource id (best-effort).

        Empty dict on any error -- utilization is enrichment only and must
        never crash a scan.
        """
        if not resource_ids:
            return {}
        try:
            return await self._fetch_utilization(resource_ids, window_days)
        except Exception:  # noqa: BLE001 -- enrichment must never crash callers
            logger.warning(
                "%s utilization fetch failed -- continuing without metrics",
                type(self).__name__,
                exc_info=True,
            )
            return {}


class NullMetricsProvider(MetricsProvider):
    """No-op provider (returns no utilization)."""

    async def _fetch_utilization(
        self, resource_ids: Sequence[str], window_days: int
    ) -> dict[str, ResourceUtilization]:
        """Return no utilization."""
        return {}
