"""Tests for GcpCostProvider -- google-cloud bigquery/billing fully mocked."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from cloudguardiq.billing.gcp_cost_provider import GcpCostProvider

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


def _money(units: int, nanos: int) -> SimpleNamespace:
    return SimpleNamespace(units=units, nanos=nanos, currency_code="USD")


def _sku(
    description: str,
    regions: list[str],
    units: int,
    nanos: int,
    usage_unit: str,
) -> SimpleNamespace:
    tier = SimpleNamespace(unit_price=_money(units, nanos))
    pricing_expression = SimpleNamespace(usage_unit=usage_unit, tiered_rates=[tier])
    pricing_info = SimpleNamespace(pricing_expression=pricing_expression)
    return SimpleNamespace(
        description=description,
        service_regions=regions,
        pricing_info=[pricing_info],
    )


class _FakeCatalog:
    """Fake CloudCatalogClient."""

    def __init__(self, skus: list, raise_exc: Exception | None = None) -> None:
        self._skus = skus
        self._raise = raise_exc
        self.list_skus_calls = 0

    def list_services(self):  # noqa: ANN201
        return [SimpleNamespace(name="services/6F81-5844-456A", display_name="Compute Engine")]

    def list_skus(self, parent: str):  # noqa: ANN201
        self.list_skus_calls += 1
        if self._raise is not None:
            raise self._raise
        return list(self._skus)


class _FakeQueryJob:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def result(self):  # noqa: ANN201
        return list(self._rows)


class _FakeBigQuery:
    def __init__(self, rows: list[dict] | None = None, raise_exc: Exception | None = None) -> None:
        self._rows = rows or []
        self._raise = raise_exc
        self.queries: list[str] = []

    def query(self, sql: str):  # noqa: ANN201
        self.queries.append(sql)
        if self._raise is not None:
            raise self._raise
        return _FakeQueryJob(self._rows)


def _provider(*, catalog=None, bq=None, table: str | None = None) -> GcpCostProvider:
    return GcpCostProvider(
        project_id="proj-123",
        billing_export_table=table,
        catalog_client=catalog,
        bigquery_client=bq,
    )


# ---------------------------------------------------------------------------
# Actual cost (BigQuery billing export)
# ---------------------------------------------------------------------------


class TestActualCost:
    @pytest.mark.asyncio
    async def test_export_rows_parsed(self) -> None:
        bq = _FakeBigQuery(
            rows=[
                {"resource_name": "vm-A", "cost": 42.5},
                {"resource_name": "disk-B", "cost": 8.0},
            ]
        )
        table = "my-proj.billing.gcp_billing_export_v1_ABCDEF"
        prov = _provider(bq=bq, table=table)
        out = await prov.get_actual_cost(["vm-A", "disk-B"])
        assert out == {"vm-a": 42.5, "disk-b": 8.0}
        # The configured export table id is referenced in the query.
        assert table in bq.queries[0]

    @pytest.mark.asyncio
    async def test_missing_table_returns_empty(self) -> None:
        bq = _FakeBigQuery(rows=[{"resource_name": "vm-A", "cost": 1.0}])
        prov = _provider(bq=bq, table=None)
        assert await prov.get_actual_cost(["vm-A"]) == {}
        assert bq.queries == []

    @pytest.mark.asyncio
    async def test_query_failure_returns_empty(self) -> None:
        bq = _FakeBigQuery(raise_exc=RuntimeError("Access Denied"))
        prov = _provider(bq=bq, table="d.t")
        assert await prov.get_actual_cost(["vm-A"]) == {}

    @pytest.mark.asyncio
    async def test_empty_ids_short_circuits(self) -> None:
        bq = _FakeBigQuery(raise_exc=RuntimeError("should not run"))
        prov = _provider(bq=bq, table="d.t")
        assert await prov.get_actual_cost([]) == {}
        assert bq.queries == []


# ---------------------------------------------------------------------------
# List price (Cloud Billing Catalog)
# ---------------------------------------------------------------------------


class TestListPrice:
    @pytest.mark.asyncio
    async def test_disk_per_gib_month_times_size(self) -> None:
        # pd-ssd capacity: $0.17/GiB-month encoded as units=0 nanos=170,000,000.
        catalog = _FakeCatalog(
            skus=[
                _sku("SSD backed PD Capacity", ["us-central1"], 0, 170_000_000, "GiBy.mo"),
            ]
        )
        prov = _provider(catalog=catalog)
        price = await prov.get_list_price("pd:pd-ssd:500", "us-central1")
        assert price == pytest.approx(85.0)  # 0.17 * 500

    @pytest.mark.asyncio
    async def test_machine_type_hourly_to_monthly(self) -> None:
        # $0.067/hour encoded as units=0 nanos=67,000,000.
        catalog = _FakeCatalog(
            skus=[
                _sku("N1 Predefined Instance n1-standard-2", ["us-central1"], 0, 67_000_000, "h"),
            ]
        )
        prov = _provider(catalog=catalog)
        price = await prov.get_list_price("gce:n1-standard-2", "us-central1")
        assert price == pytest.approx(round(0.067 * 730, 2))

    @pytest.mark.asyncio
    async def test_region_mismatch_falls_back_to_catalog(self) -> None:
        # SKU only priced for europe-west1; pd-ssd request for us-central1 misses
        # the live API and falls back to the static catalog ($0.17/GiB * 100).
        catalog = _FakeCatalog(
            skus=[
                _sku("SSD backed PD Capacity", ["europe-west1"], 0, 170_000_000, "GiBy.mo"),
            ]
        )
        prov = _provider(catalog=catalog)
        price = await prov.get_list_price("pd:pd-ssd:100", "us-central1")
        assert price == pytest.approx(17.0)

    @pytest.mark.asyncio
    async def test_catalog_failure_disk_uses_static_fallback(self) -> None:
        catalog = _FakeCatalog(skus=[], raise_exc=RuntimeError("denied"))
        prov = _provider(catalog=catalog)
        # pd-balanced @ $0.10/GiB * 200 = $20 from the static catalog.
        price = await prov.get_list_price("pd:pd-balanced:200", "us-central1")
        assert price == pytest.approx(20.0)

    @pytest.mark.asyncio
    async def test_caches_repeat_lookups(self) -> None:
        catalog = _FakeCatalog(
            skus=[_sku("N1 Predefined Instance n1-standard-2", ["us-central1"], 0, 67_000_000, "h")]
        )
        prov = _provider(catalog=catalog)
        await prov.get_list_price("gce:n1-standard-2", "us-central1")
        await prov.get_list_price("gce:n1-standard-2", "us-central1")
        assert catalog.list_skus_calls == 1


# ---------------------------------------------------------------------------
# GCE rightsizing
# ---------------------------------------------------------------------------


class TestRightsizing:
    @pytest.mark.asyncio
    async def test_delta_to_next_machine_down(self) -> None:
        catalog = _FakeCatalog(
            skus=[
                _sku("N1 Predefined Instance n1-standard-4", ["us-central1"], 0, 134_000_000, "h"),
                _sku("N1 Predefined Instance n1-standard-2", ["us-central1"], 0, 67_000_000, "h"),
            ]
        )
        prov = _provider(catalog=catalog)
        savings = await prov.estimate_gce_rightsizing_savings("n1-standard-4", "us-central1")
        expected = round(0.134 * 730, 2) - round(0.067 * 730, 2)
        assert savings == pytest.approx(round(expected, 2))

    @pytest.mark.asyncio
    async def test_unknown_machine_returns_zero(self) -> None:
        catalog = _FakeCatalog(skus=[])
        prov = _provider(catalog=catalog)
        assert await prov.estimate_gce_rightsizing_savings("f1-micro", "us-central1") == 0.0

    @pytest.mark.asyncio
    async def test_missing_price_returns_zero(self) -> None:
        # Only the larger machine is priced; smaller missing -> 0 savings.
        catalog = _FakeCatalog(
            skus=[
                _sku(
                    "N1 Predefined Instance n1-standard-4",
                    ["us-central1"],
                    0,
                    134_000_000,
                    "h",
                )
            ]
        )
        prov = _provider(catalog=catalog)
        assert await prov.estimate_gce_rightsizing_savings("n1-standard-4", "us-central1") == 0.0
