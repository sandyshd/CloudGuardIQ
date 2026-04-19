"""Tests for the CloudGuardIQ FastAPI application."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from cloudguardiq.api.main import app


@pytest.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health_returns_200(self, client: AsyncClient) -> None:
        response = await client.get("/health")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_health_body(self, client: AsyncClient) -> None:
        response = await client.get("/health")
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "0.1.0"


class TestScanTrigger:
    @pytest.mark.asyncio
    async def test_trigger_returns_queued(self, client: AsyncClient) -> None:
        response = await client.post(
            "/scan/trigger", json={"subscription_id": "sub-123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "queued"
        assert "scan_id" in data

    @pytest.mark.asyncio
    async def test_trigger_invalid_body(self, client: AsyncClient) -> None:
        response = await client.post("/scan/trigger", json={})
        assert response.status_code == 422


class TestFindingsEndpoints:
    @pytest.mark.asyncio
    async def test_list_findings_stub(self, client: AsyncClient) -> None:
        response = await client.get("/findings")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    @pytest.mark.asyncio
    async def test_get_finding_stub(self, client: AsyncClient) -> None:
        response = await client.get("/findings/abc-123")
        assert response.status_code == 200
        data = response.json()
        assert data["card_id"] == "abc-123"

    @pytest.mark.asyncio
    async def test_get_finding_terraform(self, client: AsyncClient) -> None:
        response = await client.get("/findings/abc-123/terraform")
        assert response.status_code == 200
        assert "azurerm_storage_account" in response.text


class TestSubscriptions:
    @pytest.mark.asyncio
    async def test_list_subscriptions(self, client: AsyncClient) -> None:
        response = await client.get("/subscriptions")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert data[0]["subscription_id"] == "sub-stub"
