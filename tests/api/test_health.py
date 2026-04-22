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
        # Verify it returns FindingResult objects
        assert "finding_id" in data[0]
        assert "severity" in data[0]
        assert "rule_id" in data[0]

    @pytest.mark.asyncio
    async def test_get_finding_by_id(self, client: AsyncClient) -> None:
        # First get a valid finding_id from the list
        list_resp = await client.get("/findings")
        findings = list_resp.json()
        finding_id = findings[0]["finding_id"]

        response = await client.get(f"/findings/{finding_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["finding_id"] == finding_id

    @pytest.mark.asyncio
    async def test_get_finding_not_found(self, client: AsyncClient) -> None:
        response = await client.get("/findings/nonexistent-id")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_finding_remediation(self, client: AsyncClient) -> None:
        # Get a valid finding_id first
        list_resp = await client.get("/findings")
        findings = list_resp.json()
        finding_id = findings[0]["finding_id"]

        response = await client.get(f"/findings/{finding_id}/remediation")
        assert response.status_code == 200
        data = response.json()
        assert "card_id" in data
        assert "terraform_fix" in data

    @pytest.mark.asyncio
    async def test_get_finding_terraform(self, client: AsyncClient) -> None:
        response = await client.get("/findings/any-id/terraform")
        assert response.status_code == 200
        assert "azurerm_storage_account" in response.text


class TestSubscriptions:
    @pytest.mark.asyncio
    async def test_list_subscriptions(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000001")
        response = await client.get("/subscriptions")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert data[0]["id"] == "00000000-0000-0000-0000-000000000001"
        assert data[0]["display_name"] == "00000000-0000-0000-0000-000000000001"

    @pytest.mark.asyncio
    async def test_list_subscriptions_empty_when_unconfigured(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
        response = await client.get("/subscriptions")
        assert response.status_code == 200
        assert response.json() == []
