"""CloudGuardIQ -- CloudWatch implementation of :class:`MetricsProvider`.

Pulls ``AWS/EC2`` ``CPUUtilization`` (already a percentage) and, when the
CloudWatch agent publishes it, ``CWAgent`` ``mem_used_percent`` via a single
``GetMetricData`` batch call. Reduced to a P95-based
:class:`ResourceUtilization` per instance.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from cloudguardiq.billing.metrics_provider import (
    MetricsProvider,
    ResourceUtilization,
    build_utilization,
)


def _instance_id(resource_id: str) -> str:
    """Extract the bare EC2 instance id from an ARN or raw id."""
    if "instance/" in resource_id:
        return resource_id.rsplit("instance/", 1)[-1]
    return resource_id


class AwsMetricsProvider(MetricsProvider):
    """CloudWatch utilization provider (CPU, optional memory)."""

    def __init__(self, region: str, *, cw_client: Any | None = None) -> None:
        self._region = region
        self._cw_client = cw_client

    def _make_client(self) -> Any:
        if self._cw_client is not None:
            return self._cw_client
        import boto3

        return boto3.client("cloudwatch", region_name=self._region)

    async def _fetch_utilization(
        self, resource_ids: Sequence[str], window_days: int
    ) -> dict[str, ResourceUtilization]:
        """Batch-fetch CPU (and optional memory) and reduce to P95 summaries."""
        client = self._make_client()
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=window_days)

        queries: list[dict[str, Any]] = []
        cpu_index: dict[str, str] = {}
        mem_index: dict[str, str] = {}
        for i, rid in enumerate(resource_ids):
            instance_id = _instance_id(rid)
            dims = [{"Name": "InstanceId", "Value": instance_id}]
            cpu_id = f"cpu_{i}"
            mem_id = f"mem_{i}"
            cpu_index[cpu_id] = rid
            mem_index[mem_id] = rid
            queries.append(
                {
                    "Id": cpu_id,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/EC2",
                            "MetricName": "CPUUtilization",
                            "Dimensions": dims,
                        },
                        "Period": 3600,
                        "Stat": "Average",
                    },
                }
            )
            queries.append(
                {
                    "Id": mem_id,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "CWAgent",
                            "MetricName": "mem_used_percent",
                            "Dimensions": dims,
                        },
                        "Period": 3600,
                        "Stat": "Average",
                    },
                    "ReturnData": True,
                }
            )

        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,
            lambda: client.get_metric_data(
                MetricDataQueries=queries, StartTime=start, EndTime=end
            ),
        )
        return self._response_to_utilization(response, cpu_index, mem_index)

    @staticmethod
    def _response_to_utilization(
        response: Any,
        cpu_index: dict[str, str],
        mem_index: dict[str, str],
    ) -> dict[str, ResourceUtilization]:
        cpu: dict[str, tuple[list[float], list[Any]]] = {}
        mem: dict[str, tuple[list[float], list[Any]]] = {}
        for result in response.get("MetricDataResults", []):
            rid_cpu = cpu_index.get(result.get("Id"))
            rid_mem = mem_index.get(result.get("Id"))
            values = result.get("Values", []) or []
            stamps = result.get("Timestamps", []) or []
            if rid_cpu is not None:
                cpu[rid_cpu] = (values, stamps)
            elif rid_mem is not None and values:
                mem[rid_mem] = (values, stamps)

        out: dict[str, ResourceUtilization] = {}
        for rid in set(cpu) | set(mem):
            cpu_vals, cpu_ts = cpu.get(rid, ([], []))
            mem_vals, mem_ts = mem.get(rid, ([], []))
            util = build_utilization(
                cpu_values=cpu_vals,
                cpu_timestamps=cpu_ts,
                mem_values=mem_vals,
                mem_timestamps=mem_ts,
            )
            if util is not None:
                out[rid.lower()] = util
        return out
