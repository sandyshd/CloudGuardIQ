"""API tests: /finops/coverage and /finops/forecast scoping + ownership."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.api.main import app
from cloudguardiq.core.config import get_settings
from cloudguardiq.core.models import FocusCostRecord

SUB_ID = "22222222-2222-2222-2222-222222222222"
TENANT = "tenant-finops"


@pytest.fixture
async def authed_client(monkeypatch) -> AsyncClient:
    monkeypatch.setenv("CLOUDGUARDIQ_AUTH_DISABLED", "false")
    get_settings.cache_clear()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=TENANT
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def _focus_rows() -> list[FocusCostRecord]:
    start = datetime(2026, 5, 1, tzinfo=timezone.utc)
    return [
        FocusCostRecord(
            tenant_id=TENANT, billing_period="2026-05",
            charge_period_start=start, charge_period_end=start,
            charge_category="Usage", effective_cost=600.0,
            sub_account_id=SUB_ID, service_category="Compute",
            commitment_discount_id="ri-1",
        ),
        FocusCostRecord(
            tenant_id=TENANT, billing_period="2026-05",
            charge_period_start=start, charge_period_end=start,
            charge_category="Usage", effective_cost=400.0,
            sub_account_id=SUB_ID, service_category="Compute",
        ),
        FocusCostRecord(
            tenant_id=TENANT, billing_period="2026-05",
            charge_period_start=start, charge_period_end=start,
            charge_category="Purchase", effective_cost=1000.0,
            sub_account_id=SUB_ID, service_category="Compute",
            commitment_discount_id="ri-1",
        ),
    ]


async def _allow_owned(_user, sub):
    return sub.lower()


@pytest.mark.asyncio
async def test_coverage_returns_summary_and_scopes_tenant(
    authed_client: AsyncClient,
) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_focus_records = AsyncMock(return_value=_focus_rows())

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned),
    ):
        r = await authed_client.get(f"/finops/coverage?subscription_id={SUB_ID}")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["coverage_pct"] == 0.6
    assert body["on_demand_eligible_cost"] == 400.0
    # tenant scoping is passed through to the repository.
    call = mock_repo.get_focus_records.call_args
    assert call.kwargs["tenant_id"] == TENANT


@pytest.mark.asyncio
async def test_forecast_returns_projection(authed_client: AsyncClient) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_focus_records = AsyncMock(return_value=_focus_rows())

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned),
    ):
        r = await authed_client.get(
            f"/finops/forecast?subscription_id={SUB_ID}&dimension=sub_account"
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, list)
    assert body[0]["key"] == SUB_ID


@pytest.mark.asyncio
async def test_coverage_enforces_ownership(authed_client: AsyncClient) -> None:
    async def _deny(_user, sub):
        raise HTTPException(
            status_code=403, detail={"error": "subscription_not_linked"}
        )

    mock_repo = AsyncMock()
    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_deny),
    ):
        r = await authed_client.get("/finops/coverage?subscription_id=not-mine")

    assert r.status_code == 403
    mock_repo.get_focus_records.assert_not_called()


@pytest.mark.asyncio
async def test_coverage_empty_without_subscription(
    authed_client: AsyncClient,
) -> None:
    with patch("cloudguardiq.api.main.get_repo", return_value=AsyncMock()):
        r = await authed_client.get("/finops/coverage")
    assert r.status_code == 200
    assert r.json()["eligible_cost"] == 0.0


@pytest.mark.asyncio
async def test_coverage_degrades_on_cosmos_failure(
    authed_client: AsyncClient,
) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_focus_records = AsyncMock(side_effect=RuntimeError("cosmos down"))

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned),
    ):
        r = await authed_client.get(f"/finops/coverage?subscription_id={SUB_ID}")

    assert r.status_code == 200
    assert r.json()["eligible_cost"] == 0.0


@pytest.mark.asyncio
async def test_forecast_empty_on_no_data(authed_client: AsyncClient) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_focus_records = AsyncMock(return_value=[])

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned),
    ):
        r = await authed_client.get(f"/finops/forecast?subscription_id={SUB_ID}")

    assert r.status_code == 200
    assert r.json() == []
