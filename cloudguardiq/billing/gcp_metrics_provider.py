"""CloudGuardIQ -- Cloud Monitoring implementation of :class:`MetricsProvider`.

Pulls ``compute.googleapis.com/instance/cpu/utilization`` (a 0-1 fraction,
scaled to a percentage) per instance via ``timeSeries.list`` and reduces to a
P95-based :class:`ResourceUtilization`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any

from cloudguardiq.billing.metrics_provider import (
    MetricsProvider,
    ResourceUtilization,
    build_utilization,
)

_CPU_METRIC = "compute.googleapis.com/instance/cpu/utilization"


class GcpMetricsProvider(MetricsProvider):
    """Cloud Monitoring utilization provider (CPU fraction -> percentage)."""

    def __init__(self, project_id: str, *, monitoring_client: Any | None = None) -> None:
        self._project_id = project_id
        self._client = monitoring_client

    def _make_client(self) -> Any:
        if self._client is not None:
            return self._client
        from google.cloud import monitoring_v3

        return monitoring_v3.MetricServiceClient()

    async def _fetch_utilization(
        self, resource_ids: Sequence[str], window_days: int
    ) -> dict[str, ResourceUtilization]:
        """Fetch per-instance CPU utilization and reduce to P95 summaries."""
        client = self._make_client()
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=window_days)
        loop = asyncio.get_running_loop()

        out: dict[str, ResourceUtilization] = {}
        for rid in resource_ids:
            series = await loop.run_in_executor(
                None, partial(self._query_one, client, rid, start, end)
            )
            util = self._series_to_utilization(series)
            if util is not None:
                out[rid.lower()] = util
        return out

    def _query_one(
        self, client: Any, resource_id: str, start: datetime, end: datetime
    ) -> Any:
        request = {
            "name": f"projects/{self._project_id}",
            "filter": (
                f'metric.type = "{_CPU_METRIC}" AND '
                f'resource.labels.instance_id = "{resource_id}"'
            ),
            "interval": {"start_time": start, "end_time": end},
        }
        return client.list_time_series(request=request)

    @staticmethod
    def _series_to_utilization(series_iter: Any) -> ResourceUtilization | None:
        values: list[float] = []
        timestamps: list[Any] = []
        for series in series_iter or []:
            for point in getattr(series, "points", None) or []:
                raw = getattr(getattr(point, "value", None), "double_value", None)
                if raw is None:
                    continue
                values.append(float(raw) * 100.0)
                interval = getattr(point, "interval", None)
                timestamps.append(getattr(interval, "end_time", None))
        return build_utilization(cpu_values=values, cpu_timestamps=timestamps)
