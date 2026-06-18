"""Tests for FOCUS billing ingestion across Azure, AWS and GCP providers.

All cloud SDK/HTTP calls are mocked -- no network, no credentials. Each
provider must map its native billing payload into FocusCostRecord rows and
return [] (logging a warning) on any failure.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from cloudguardiq.billing.aws_cost_provider import AwsCostProvider
from cloudguardiq.billing.azure_cost_provider import AzureCostProvider
from cloudguardiq.billing.cost_provider import NullCostProvider
from cloudguardiq.billing.gcp_cost_provider import GcpCostProvider
from cloudguardiq.billing.pricing import PricingService
from cloudguardiq.core.enums import CloudProvider

# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------


class _FakeAzureResponse:
    def __init__(self, columns: list[str], rows: list[list[Any]]) -> None:
        self.columns = [SimpleNamespace(name=c) for c in columns]
        self.rows = rows


class _FakeQueryUsage:
    def __init__(self, response: Any = None, *, raises: Exception | None = None) -> None:
        self._response = response
        self._raises = raises

    def __call__(self, scope: str, query_def: Any) -> Any:
        if self._raises is not None:
            raise self._raises
        return self._response


class _FakeAzureClient:
    def __init__(self, usage: _FakeQueryUsage) -> None:
        self.query = SimpleNamespace(usage=usage)


def _azure(response: Any = None, *, raises: Exception | None = None) -> AzureCostProvider:
    usage = _FakeQueryUsage(response, raises=raises)
    return AzureCostProvider(
        credential=object(),
        subscription_id="sub-123",
        pricing_service=PricingService(),
        client_factory=lambda cred: _FakeAzureClient(usage),
    )


async def test_azure_maps_rows_to_focus_records() -> None:
    response = _FakeAzureResponse(
        columns=[
            "Cost",
            "ResourceId",
            "ServiceName",
            "ResourceType",
            "ResourceLocation",
            "Currency",
        ],
        rows=[
            [
                42.5,
                "/subscriptions/sub-123/RG/A",
                "Virtual Machines",
                "Microsoft.Compute/virtualMachines",
                "eastus",
                "USD",
            ],
            [
                10.0,
                "/subscriptions/sub-123/RG/B",
                "Storage",
                "Microsoft.Storage/storageAccounts",
                "westus",
                "USD",
            ],
        ],
    )
    out = await _azure(response).get_cost_and_usage()
    assert len(out) == 2
    first = out[0]
    assert first.provider is CloudProvider.AZURE
    assert first.sub_account_id == "sub-123"
    assert first.resource_id == "/subscriptions/sub-123/rg/a"
    assert first.service_name == "Virtual Machines"
    assert first.region == "eastus"
    assert first.billed_cost == 42.5
    assert first.billing_period  # non-empty YYYY-MM


async def test_azure_failure_returns_empty(caplog: Any) -> None:
    out = await _azure(raises=RuntimeError("boom")).get_cost_and_usage()
    assert out == []
    assert any("ingestion failed" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------


class _FakeCE:
    def __init__(self, response: dict | None = None, *, raises: Exception | None = None) -> None:
        self._response = response or {}
        self._raises = raises

    def get_cost_and_usage(self, **kwargs: object) -> dict:
        if self._raises is not None:
            raise self._raises
        return self._response


def _aws(ce: _FakeCE) -> AwsCostProvider:
    return AwsCostProvider(account_id="111122223333", region="us-east-1", ce_client=ce)


async def test_aws_maps_groups_to_focus_records() -> None:
    response = {
        "ResultsByTime": [
            {
                "Groups": [
                    {
                        "Keys": ["Amazon EC2", "BoxUsage:t3.micro"],
                        "Metrics": {
                            "AmortizedCost": {"Amount": "12.34", "Unit": "USD"},
                            "UnblendedCost": {"Amount": "15.00", "Unit": "USD"},
                            "UsageQuantity": {"Amount": "720", "Unit": "Hrs"},
                        },
                    },
                ],
            },
        ],
    }
    out = await _aws(_FakeCE(response)).get_cost_and_usage()
    assert len(out) == 1
    rec = out[0]
    assert rec.provider is CloudProvider.AWS
    assert rec.sub_account_id == "111122223333"
    assert rec.service_name == "Amazon EC2"
    assert rec.sku_id == "BoxUsage:t3.micro"
    assert rec.effective_cost == 12.34
    assert rec.billed_cost == 15.0
    assert rec.usage_quantity == 720.0
    assert rec.usage_unit == "Hrs"


async def test_aws_failure_returns_empty(caplog: Any) -> None:
    out = await _aws(_FakeCE(raises=RuntimeError("ce down"))).get_cost_and_usage()
    assert out == []
    assert any("ingestion failed" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------


class _FakeJob:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def result(self) -> list[dict]:
        return list(self._rows)


class _FakeBigQuery:
    def __init__(self, rows: list[dict] | None = None, *, raises: Exception | None = None) -> None:
        self._rows = rows or []
        self._raises = raises
        self.queries: list[str] = []

    def query(self, sql: str) -> _FakeJob:
        self.queries.append(sql)
        if self._raises is not None:
            raise self._raises
        return _FakeJob(self._rows)


def _gcp(
    bq: _FakeBigQuery,
    *,
    table: str | None = "proj.ds.gcp_billing_export_v1_X",
) -> GcpCostProvider:
    return GcpCostProvider(
        project_id="proj-1",
        billing_export_table=table,
        bigquery_client=bq,
    )


async def test_gcp_maps_rows_to_focus_records() -> None:
    rows = [
        {
            "service_name": "Compute Engine",
            "sku_id": "ABCD-1234",
            "project_id": "proj-1",
            "region": "us-central1",
            "resource_name": "//compute/instances/vm-1",
            "currency": "USD",
            "billing_account_id": "01ABCD-XYZ",
            "cost": 33.21,
            "usage_amount": 100.0,
            "usage_unit": "byte-seconds",
        },
    ]
    out = await _gcp(_FakeBigQuery(rows)).get_cost_and_usage()
    assert len(out) == 1
    rec = out[0]
    assert rec.provider is CloudProvider.GCP
    assert rec.sub_account_id == "proj-1"
    assert rec.service_name == "Compute Engine"
    assert rec.sku_id == "ABCD-1234"
    assert rec.resource_id == "//compute/instances/vm-1"
    assert rec.region == "us-central1"
    assert rec.billed_cost == 33.21
    assert rec.usage_quantity == 100.0


async def test_gcp_no_table_returns_empty() -> None:
    out = await _gcp(_FakeBigQuery([]), table=None).get_cost_and_usage()
    assert out == []


async def test_gcp_failure_returns_empty(caplog: Any) -> None:
    out = await _gcp(_FakeBigQuery(raises=RuntimeError("bq down"))).get_cost_and_usage()
    assert out == []
    assert any("ingestion failed" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Null provider
# ---------------------------------------------------------------------------


async def test_null_provider_returns_empty() -> None:
    out = await NullCostProvider().get_cost_and_usage()
    assert out == []
