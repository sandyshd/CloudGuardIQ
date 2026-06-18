"""Unit tests for the provider-agnostic metrics seam."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from cloudguardiq.billing.aws_metrics_provider import AwsMetricsProvider
from cloudguardiq.billing.azure_metrics_provider import AzureMetricsProvider
from cloudguardiq.billing.gcp_metrics_provider import GcpMetricsProvider
from cloudguardiq.billing.metrics_provider import (
    MIN_OBSERVATION_DAYS,
    MIN_SAMPLE_COUNT,
    NullMetricsProvider,
    ResourceUtilization,
    build_utilization,
    is_observation_sufficient,
    percentile,
)

_BASE = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _azure_point(ts: datetime, avg: float) -> SimpleNamespace:
    return SimpleNamespace(time_stamp=ts, average=avg)


def _azure_metric(name: str, points: list[SimpleNamespace]) -> SimpleNamespace:
    return SimpleNamespace(
        name=SimpleNamespace(value=name),
        timeseries=[SimpleNamespace(data=points)],
    )


class _FakeMetricsApi:
    def __init__(self, response: SimpleNamespace) -> None:
        self._response = response
        self.calls: list[tuple] = []

    def list(self, resource_uri: str, **kwargs: object) -> SimpleNamespace:
        self.calls.append((resource_uri, kwargs))
        return self._response


class _FakeMonitorClient:
    def __init__(self, response: SimpleNamespace) -> None:
        self.metrics = _FakeMetricsApi(response)


def test_percentile_interpolates() -> None:
    assert percentile([10, 20, 30, 40], 95) == 38.5
    assert percentile([], 95) is None
    assert percentile([5], 95) == 5.0


def test_build_utilization_returns_none_when_empty() -> None:
    assert build_utilization(cpu_values=[], mem_values=[]) is None


def test_is_observation_sufficient_guard() -> None:
    ok = {
        "metric_sample_count": MIN_SAMPLE_COUNT,
        "metric_observation_days": MIN_OBSERVATION_DAYS,
    }
    assert is_observation_sufficient(ok) is True
    assert is_observation_sufficient({"metric_sample_count": 5,
                                      "metric_observation_days": 10}) is False
    assert is_observation_sufficient({"metric_observation_days": 10}) is False
    assert is_observation_sufficient({}) is False


async def test_null_provider_returns_empty() -> None:
    provider = NullMetricsProvider()
    assert await provider.get_utilization(["a", "b"]) == {}


async def test_get_utilization_short_circuits_empty_ids() -> None:
    provider = NullMetricsProvider()
    assert await provider.get_utilization([]) == {}


async def test_azure_provider_maps_metrics_payload() -> None:
    points = [_azure_point(_BASE + timedelta(hours=i), float(i % 100))
              for i in range(240)]
    response = SimpleNamespace(value=[_azure_metric("Percentage CPU", points)])

    provider = AzureMetricsProvider(
        object(),
        "sub-1",
        client_factory=lambda _cred: _FakeMonitorClient(response),
    )
    result = await provider.get_utilization(
        ["/subscriptions/sub-1/resourceGroups/RG/providers/"
         "Microsoft.Compute/virtualMachines/VM1"]
    )

    key = ("/subscriptions/sub-1/resourcegroups/rg/providers/"
           "microsoft.compute/virtualmachines/vm1")
    assert key in result
    util = result[key]
    assert isinstance(util, ResourceUtilization)
    assert util.sample_count == 240
    assert util.observation_days == 10
    assert util.p95_cpu is not None
    assert 0.0 <= util.p95_cpu <= 100.0
    # Azure host memory metric is bytes-free, so memory stays unset.
    assert util.p95_mem is None


async def test_azure_provider_no_credential_returns_empty() -> None:
    provider = AzureMetricsProvider(None, "sub-1")
    assert await provider.get_utilization(["x"]) == {}


async def test_aws_provider_maps_get_metric_data() -> None:
    stamps = [_BASE + timedelta(hours=i) for i in range(48)]

    class _FakeCw:
        def get_metric_data(self, **kwargs: object) -> dict:
            return {
                "MetricDataResults": [
                    {"Id": "cpu_0", "Values": [3.0] * 48, "Timestamps": stamps},
                    {"Id": "mem_0", "Values": [12.0] * 48, "Timestamps": stamps},
                ]
            }

    provider = AwsMetricsProvider("us-east-1", cw_client=_FakeCw())
    result = await provider.get_utilization(
        ["arn:aws:ec2:us-east-1:1:instance/i-abc"]
    )
    util = result["arn:aws:ec2:us-east-1:1:instance/i-abc"]
    assert util.p95_cpu == 3.0
    assert util.p95_mem == 12.0
    assert util.sample_count == 48


async def test_gcp_provider_scales_fraction_to_percent() -> None:
    points = [
        SimpleNamespace(
            value=SimpleNamespace(double_value=0.04),
            interval=SimpleNamespace(end_time=_BASE + timedelta(hours=i)),
        )
        for i in range(48)
    ]

    class _FakeMonitoring:
        def list_time_series(self, **kwargs: object) -> list[SimpleNamespace]:
            return [SimpleNamespace(points=points)]

    provider = GcpMetricsProvider("proj-1", monitoring_client=_FakeMonitoring())
    result = await provider.get_utilization(["12345"])
    util = result["12345"]
    assert util.p95_cpu == 4.0
    assert util.sample_count == 48
