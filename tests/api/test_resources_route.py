"""Tests for the GET /resources endpoint (Resources page backend)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.api.main import app
from cloudguardiq.core.config import get_settings
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import ResourceSnapshot

SUB_ID = "11111111-1111-1111-1111-111111111111"
TENANT = "tenant-resources"


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


def _sample_snapshot() -> ResourceSnapshot:
    return ResourceSnapshot(
        tenant_id=TENANT,
        subscription_id=SUB_ID,
        resource_group="rg1",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="sa1",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        cost_monthly=12.5,
        tags={"env": "prod"},
    )


@pytest.mark.asyncio
async def test_list_resources_returns_snapshots(authed_client: AsyncClient) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_snapshots = AsyncMock(return_value=[_sample_snapshot()])

    async def _allow_owned(_user, sub):
        return sub.lower()

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned),
    ):
        r = await authed_client.get("/resources", params={"subscription_id": SUB_ID})

    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 1
    assert body[0]["resource_name"] == "sa1"
    assert body[0]["cost_monthly"] == 12.5

    call = mock_repo.get_snapshots.call_args
    assert call.kwargs["tenant_id"] == TENANT


@pytest.mark.asyncio
async def test_list_resources_no_subscription_returns_empty(
    authed_client: AsyncClient,
) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_snapshots = AsyncMock(return_value=[])

    with patch("cloudguardiq.api.main.get_repo", return_value=mock_repo):
        r = await authed_client.get("/resources")

    assert r.status_code == 200, r.text
    assert r.json() == []
    mock_repo.get_snapshots.assert_not_called()


@pytest.mark.asyncio
async def test_list_resources_degrades_on_repo_error(
    authed_client: AsyncClient,
) -> None:
    mock_repo = AsyncMock()
    mock_repo.get_snapshots = AsyncMock(side_effect=RuntimeError("cosmos down"))

    async def _allow_owned(_user, sub):
        return sub.lower()

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned),
    ):
        r = await authed_client.get("/resources", params={"subscription_id": SUB_ID})

    assert r.status_code == 200, r.text
    assert r.json() == []
