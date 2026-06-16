"""Tests for AwsCostProvider -- boto3 'ce' and 'pricing' fully mocked."""

from __future__ import annotations

import json

import pytest

from cloudguardiq.billing.aws_cost_provider import AwsCostProvider


def _ondemand(usd: float, unit: str = "Hrs") -> str:
    """Build a single Price List JSON string with one on-demand dimension."""
    return json.dumps(
        {
            "product": {"attributes": {}},
            "terms": {
                "OnDemand": {
                    "TERM1": {
                        "priceDimensions": {
                            "DIM1": {
                                "unit": unit,
                                "pricePerUnit": {"USD": str(usd)},
                            }
                        }
                    }
                }
            },
        }
    )


class _FakeCE:
    """Fake Cost Explorer client."""

    def __init__(self, response: dict | None = None, raise_exc: Exception | None = None) -> None:
        self._response = response or {}
        self._raise = raise_exc
        self.calls: list[dict] = []

    def get_cost_and_usage(self, **kwargs: object) -> dict:
        self.calls.append(kwargs)
        if self._raise is not None:
            raise self._raise
        return self._response


class _FakePricing:
    """Fake Price List client driven by a responder callback."""

    def __init__(self, responder) -> None:
        self._responder = responder
        self.calls: list[tuple[str, dict]] = []

    def get_products(self, **kwargs: object) -> dict:
        service_code = kwargs["ServiceCode"]
        filters = kwargs.get("Filters") or []
        fd = {f["Field"]: f["Value"] for f in filters}  # type: ignore[union-attr]
        self.calls.append((service_code, fd))  # type: ignore[arg-type]
        return {"PriceList": self._responder(service_code, fd)}


def _provider(*, ce=None, pricing=None) -> AwsCostProvider:
    return AwsCostProvider(
        account_id="111122223333",
        region="us-east-1",
        ce_client=ce,
        pricing_client=pricing,
    )


# ---------------------------------------------------------------------------
# Actual cost (Cost Explorer)
# ---------------------------------------------------------------------------


class TestActualCost:
    @pytest.mark.asyncio
    async def test_resource_level_rows_parsed(self) -> None:
        ce = _FakeCE(
            response={
                "ResultsByTime": [
                    {
                        "Groups": [
                            {
                                "Keys": ["i-ABC"],
                                "Metrics": {"AmortizedCost": {"Amount": "42.5", "Unit": "USD"}},
                            },
                            {
                                "Keys": ["vol-XYZ"],
                                "Metrics": {"AmortizedCost": {"Amount": "8.0", "Unit": "USD"}},
                            },
                        ]
                    }
                ]
            }
        )
        prov = _provider(ce=ce)
        out = await prov.get_actual_cost(["i-ABC", "vol-XYZ"])
        assert out == {"i-abc": 42.5, "vol-xyz": 8.0}
        # AmortizedCost metric requested (FOCUS EffectiveCost alignment).
        assert ce.calls[0]["Metrics"] == ["AmortizedCost"]
        assert ce.calls[0]["GroupBy"] == [{"Type": "DIMENSION", "Key": "RESOURCE_ID"}]

    @pytest.mark.asyncio
    async def test_iam_denied_returns_empty(self) -> None:
        ce = _FakeCE(raise_exc=RuntimeError("AccessDeniedException"))
        prov = _provider(ce=ce)
        assert await prov.get_actual_cost(["i-ABC"]) == {}

    @pytest.mark.asyncio
    async def test_no_resource_rows_returns_empty(self) -> None:
        ce = _FakeCE(response={"ResultsByTime": [{"Groups": []}]})
        prov = _provider(ce=ce)
        assert await prov.get_actual_cost(["i-ABC"]) == {}

    @pytest.mark.asyncio
    async def test_empty_ids_short_circuits(self) -> None:
        ce = _FakeCE(raise_exc=RuntimeError("should not be called"))
        prov = _provider(ce=ce)
        assert await prov.get_actual_cost([]) == {}
        assert ce.calls == []


# ---------------------------------------------------------------------------
# List price (Price List Query API)
# ---------------------------------------------------------------------------


class TestListPrice:
    @pytest.mark.asyncio
    async def test_ebs_per_gb_times_size(self) -> None:
        def responder(service, fd):
            if service == "AmazonEC2" and fd.get("volumeApiName") == "gp3":
                return [_ondemand(0.08, unit="GB-Mo")]
            return []

        pricing = _FakePricing(responder)
        prov = _provider(pricing=pricing)
        # gp3 @ $0.08/GB-mo * 100 GiB = $8.00
        price = await prov.get_list_price("ebs:gp3:100", "us-east-1")
        assert price == pytest.approx(8.0)
        # Region targeted is the resource region.
        assert pricing.calls[0][1]["regionCode"] == "us-east-1"

    @pytest.mark.asyncio
    async def test_ec2_instance_hourly_to_monthly(self) -> None:
        def responder(service, fd):
            if fd.get("instanceType") == "m5.large":
                return [_ondemand(0.096)]
            return []

        pricing = _FakePricing(responder)
        prov = _provider(pricing=pricing)
        price = await prov.get_list_price("ec2:m5.large", "us-east-1")
        assert price == pytest.approx(round(0.096 * 730, 2))

    @pytest.mark.asyncio
    async def test_idle_eip_hourly_to_monthly(self) -> None:
        def responder(service, fd):
            if service == "AmazonVPC":
                return [_ondemand(0.005)]
            return []

        pricing = _FakePricing(responder)
        prov = _provider(pricing=pricing)
        price = await prov.get_list_price("eip:idle", "us-east-1")
        assert price == pytest.approx(round(0.005 * 730, 2))

    @pytest.mark.asyncio
    async def test_ebs_static_fallback_when_api_empty(self) -> None:
        pricing = _FakePricing(lambda service, fd: [])  # API miss
        prov = _provider(pricing=pricing)
        # Falls back to static catalog (gp3 @ $0.08/GB * 100 = $8).
        price = await prov.get_list_price("ebs:gp3:100", "us-east-1")
        assert price == pytest.approx(8.0)

    @pytest.mark.asyncio
    async def test_caches_repeat_lookups(self) -> None:
        def responder(service, fd):
            return [_ondemand(0.096)]

        pricing = _FakePricing(responder)
        prov = _provider(pricing=pricing)
        await prov.get_list_price("ec2:m5.large", "us-east-1")
        await prov.get_list_price("ec2:m5.large", "us-east-1")
        assert len(pricing.calls) == 1


# ---------------------------------------------------------------------------
# EC2 rightsizing
# ---------------------------------------------------------------------------


class TestRightsizing:
    @pytest.mark.asyncio
    async def test_delta_to_next_size_down(self) -> None:
        prices = {"m5.xlarge": 0.192, "m5.large": 0.096}

        def responder(service, fd):
            it = fd.get("instanceType")
            return [_ondemand(prices[it])] if it in prices else []

        pricing = _FakePricing(responder)
        prov = _provider(pricing=pricing)
        savings = await prov.estimate_ec2_rightsizing_savings("m5.xlarge", "us-east-1")
        expected = round(0.192 * 730, 2) - round(0.096 * 730, 2)
        assert savings == pytest.approx(round(expected, 2))

    @pytest.mark.asyncio
    async def test_unknown_size_returns_zero(self) -> None:
        pricing = _FakePricing(lambda s, fd: [])
        prov = _provider(pricing=pricing)
        assert await prov.estimate_ec2_rightsizing_savings("t3.nano", "us-east-1") == 0.0

    @pytest.mark.asyncio
    async def test_missing_price_returns_zero(self) -> None:
        def responder(service, fd):
            # Only the larger size is priced; smaller missing.
            return [_ondemand(0.192)] if fd.get("instanceType") == "m5.xlarge" else []

        pricing = _FakePricing(responder)
        prov = _provider(pricing=pricing)
        assert await prov.estimate_ec2_rightsizing_savings("m5.xlarge", "us-east-1") == 0.0
