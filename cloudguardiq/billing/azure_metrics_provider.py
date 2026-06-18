"""CloudGuardIQ -- Azure Monitor implementation of :class:`MetricsProvider`.

Uses ``azure-mgmt-monitor`` (the declared dependency) to pull "Percentage CPU"
averages per VM over the observation window. Calls run in a thread executor and
are fanned out with :func:`asyncio.gather` (conceptually a batch), then reduced
to a P95-based :class:`ResourceUtilization`.

Memory note: Azure's host metric is "Available Memory Bytes" (free bytes), not
a percentage; without the VM's total RAM it cannot be normalized, so memory is
left unset. Idle detection (CPU-only) is unaffected.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any

from azure.core.credentials import TokenCredential
from azure.mgmt.monitor import MonitorManagementClient

from cloudguardiq.billing.metrics_provider import (
    MetricsProvider,
    ResourceUtilization,
    build_utilization,
)

_CPU_METRIC = "Percentage CPU"


class AzureMetricsProvider(MetricsProvider):
    """Azure Monitor utilization provider (per-VM metrics, P95 reduced)."""

    def __init__(
        self,
        credential: TokenCredential | None,
        subscription_id: str,
        *,
        client_factory: Callable[[TokenCredential | None], Any] | None = None,
    ) -> None:
        self._credential = credential
        self._subscription_id = subscription_id
        self._client_factory = client_factory

    def _make_client(self) -> Any:
        if self._client_factory is not None:
            return self._client_factory(self._credential)
        assert self._credential is not None
        return MonitorManagementClient(self._credential, self._subscription_id)

    async def _fetch_utilization(
        self, resource_ids: Sequence[str], window_days: int
    ) -> dict[str, ResourceUtilization]:
        """Fetch per-VM CPU utilization and reduce to P95 summaries."""
        if self._credential is None and self._client_factory is None:
            return {}

        client = self._make_client()
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=window_days)
        timespan = f"{start.isoformat()}/{end.isoformat()}"

        loop = asyncio.get_running_loop()
        tasks = [
            loop.run_in_executor(None, partial(self._query_one, client, rid, timespan))
            for rid in resource_ids
        ]
        results = await asyncio.gather(*tasks)

        out: dict[str, ResourceUtilization] = {}
        for rid, util in zip(resource_ids, results, strict=True):
            if util is not None:
                out[rid.lower()] = util
        return out

    def _query_one(
        self, client: Any, resource_id: str, timespan: str
    ) -> ResourceUtilization | None:
        response = client.metrics.list(
            resource_id,
            timespan=timespan,
            interval="PT1H",
            metricnames=_CPU_METRIC,
            aggregation="Average",
        )
        return self._response_to_utilization(response)

    @staticmethod
    def _response_to_utilization(response: Any) -> ResourceUtilization | None:
        cpu_values: list[float] = []
        cpu_timestamps: list[Any] = []
        for metric in getattr(response, "value", None) or []:
            name = getattr(getattr(metric, "name", None), "value", None)
            if name != _CPU_METRIC:
                continue
            for series in getattr(metric, "timeseries", None) or []:
                for point in getattr(series, "data", None) or []:
                    avg = getattr(point, "average", None)
                    if avg is None:
                        continue
                    cpu_values.append(float(avg))
                    cpu_timestamps.append(getattr(point, "time_stamp", None))
        return build_utilization(cpu_values=cpu_values, cpu_timestamps=cpu_timestamps)
