"""API tests: FinOps Operate routes (allocation, budgets, anomalies, units)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.api.main import app
from cloudguardiq.core.config import get_settings
from cloudguardiq.core.models import FocusCostRecord
from cloudguardiq.finops.budgets import Budget

SUB_ID = "33333333-3333-3333-3333-333333333333"
TENANT = "tenant-operate"


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
    base = datetime(2026, 5, 1, tzinfo=timezone.utc)
    rows: list[FocusCostRecord] = []
    for day in range(10):
        start = base + timedelta(days=day)
        rows.append(
            FocusCostRecord(
                tenant_id=TENANT, billing_period="2026-05",
                charge_period_start=start, charge_period_end=start,
                charge_category="Usage", effective_cost=50.0,
                sub_account_id=SUB_ID, service_category="Compute",
                service_name="VM", tags={"team": "payments"},
            )
        )
    return rows


async def _allow_owned(_user, sub):
    return sub.lower()


@pytest.mark.asyncio
async def test_allocation_groups_and_scopes_tenant(
    authed_client: AsyncClient,
) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_focus_records = AsyncMock(return_value=_focus_rows())
    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch(
            "cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned
        ),
    ):
        r = await authed_client.get(
            f"/finops/allocation?subscription_id={SUB_ID}&dimension=team"
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dimension"] == "team"
    assert body["coverage_pct"] == 1.0
    assert body["groups"][0]["key"] == "payments"
    assert mock_repo.get_focus_records.call_args.kwargs["tenant_id"] == TENANT


@pytest.mark.asyncio
async def test_allocation_empty_without_subscription(
    authed_client: AsyncClient,
) -> None:
    with patch("cloudguardiq.api.main.get_repo", return_value=AsyncMock()):
        r = await authed_client.get("/finops/allocation?dimension=team")
    assert r.status_code == 200
    assert r.json()["total_cost"] == 0.0


@pytest.mark.asyncio
async def test_allocation_enforces_ownership(authed_client: AsyncClient) -> None:
    async def _deny(_user, sub):
        raise HTTPException(status_code=403, detail={"error": "not_linked"})

    mock_repo = AsyncMock()
    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_deny),
    ):
        r = await authed_client.get("/finops/allocation?subscription_id=nope")
    assert r.status_code == 403
    mock_repo.get_focus_records.assert_not_called()


@pytest.mark.asyncio
async def test_allocation_degrades_on_cosmos_failure(
    authed_client: AsyncClient,
) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_focus_records = AsyncMock(side_effect=RuntimeError("down"))
    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch(
            "cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned
        ),
    ):
        r = await authed_client.get(f"/finops/allocation?subscription_id={SUB_ID}")
    assert r.status_code == 200
    assert r.json()["total_cost"] == 0.0


@pytest.mark.asyncio
async def test_tag_coverage_returns_map(authed_client: AsyncClient) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_focus_records = AsyncMock(return_value=_focus_rows())
    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch(
            "cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned
        ),
    ):
        r = await authed_client.get(
            f"/finops/coverage-tags?subscription_id={SUB_ID}"
        )
    assert r.status_code == 200
    body = r.json()
    assert body["team"] == 1.0
    assert body["app"] == 0.0


@pytest.mark.asyncio
async def test_anomalies_empty_on_no_data(authed_client: AsyncClient) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_focus_records = AsyncMock(return_value=[])
    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch(
            "cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned
        ),
    ):
        r = await authed_client.get(f"/finops/anomalies?subscription_id={SUB_ID}")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_unit_economics_computes_cost_per_unit(
    authed_client: AsyncClient,
) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_focus_records = AsyncMock(return_value=_focus_rows())
    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch(
            "cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned
        ),
    ):
        r = await authed_client.get(
            f"/finops/unit-economics?subscription_id={SUB_ID}&units=100"
            "&unit_label=customer"
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["units"] == 100.0
    assert body["total_cost"] == 500.0
    assert body["cost_per_unit"] == 5.0


@pytest.mark.asyncio
async def test_unit_economics_safe_when_units_zero(
    authed_client: AsyncClient,
) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_focus_records = AsyncMock(return_value=_focus_rows())
    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch(
            "cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned
        ),
    ):
        r = await authed_client.get(
            f"/finops/unit-economics?subscription_id={SUB_ID}&units=0"
        )
    assert r.status_code == 200
    assert r.json()["cost_per_unit"] == 0.0


@pytest.mark.asyncio
async def test_list_budgets_scopes_tenant(authed_client: AsyncClient) -> None:
    budget = Budget(
        budget_id="b1", tenant_id=TENANT, subscription_id=SUB_ID,
        name="Compute", dimension="sub_account", amount_monthly=1000.0,
    )
    mock_repo = AsyncMock()
    mock_repo.list_budgets = AsyncMock(return_value=[budget])
    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch(
            "cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned
        ),
    ):
        r = await authed_client.get(
            f"/finops/budgets?subscription_id={SUB_ID}"
        )
    assert r.status_code == 200, r.text
    assert r.json()[0]["budget_id"] == "b1"
    assert mock_repo.list_budgets.call_args.args[0] == TENANT


@pytest.mark.asyncio
async def test_create_budget_binds_tenant(authed_client: AsyncClient) -> None:
    mock_repo = AsyncMock()
    mock_repo.upsert_budget = AsyncMock(return_value="b9")
    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch(
            "cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned
        ),
    ):
        r = await authed_client.post(
            "/finops/budgets",
            json={
                "budget_id": "b9",
                "subscription_id": SUB_ID,
                "name": "Prod",
                "dimension": "sub_account",
                "amount_monthly": 2000.0,
            },
        )
    assert r.status_code == 201, r.text
    assert r.json()["tenant_id"] == TENANT
    saved = mock_repo.upsert_budget.call_args.args[0]
    assert saved.tenant_id == TENANT


@pytest.mark.asyncio
async def test_delete_budget_returns_204(authed_client: AsyncClient) -> None:
    mock_repo = AsyncMock()
    mock_repo.delete_budget = AsyncMock(return_value=None)
    with patch("cloudguardiq.api.main.get_repo", return_value=mock_repo):
        r = await authed_client.delete("/finops/budgets/b1")
    assert r.status_code == 204
    assert mock_repo.delete_budget.call_args.args[0] == TENANT


@pytest.mark.asyncio
async def test_budget_status_breach(authed_client: AsyncClient) -> None:
    budget = Budget(
        budget_id="b1", tenant_id=TENANT, subscription_id=SUB_ID,
        name="Tight", dimension="sub_account", amount_monthly=400.0,
    )
    mock_repo = AsyncMock()
    mock_repo.list_budgets = AsyncMock(return_value=[budget])
    mock_repo.get_focus_records = AsyncMock(return_value=_focus_rows())
    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch(
            "cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned
        ),
    ):
        r = await authed_client.get(
            f"/finops/budgets/status?subscription_id={SUB_ID}"
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body[0]["status"] == "BREACH"
    assert body[0]["actual_cost"] == 500.0


@pytest.mark.asyncio
async def test_budget_status_degrades_on_failure(
    authed_client: AsyncClient,
) -> None:
    mock_repo = AsyncMock()
    mock_repo.list_budgets = AsyncMock(side_effect=RuntimeError("down"))
    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch(
            "cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned
        ),
    ):
        r = await authed_client.get(
            f"/finops/budgets/status?subscription_id={SUB_ID}"
        )
    assert r.status_code == 200
    assert r.json() == []
