"""Tests for POST /findings/{id}/generate-remediation endpoint."""

from __future__ import annotations

import sys
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from cloudguardiq.api.main import app
from cloudguardiq.core.models import RemediationCard


def _fake_card() -> RemediationCard:
    return RemediationCard(
        card_id=str(uuid.uuid4()),
        narrative="AI-generated narrative",
        terraform_fix='resource "azurerm_storage_account" "example" {}',
        cli_fix="az storage account update --https-only true",
        confidence_qualifier="high",
        estimated_savings_usd=120.0,
    )


@pytest.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestGenerateRemediation:
    @pytest.mark.asyncio
    async def test_generates_card_for_demo_finding(
        self,
        client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """POST should call AI engine and return a card for a known finding."""
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com")

        list_resp = await client.get("/findings")
        finding_id = list_resp.json()[0]["finding_id"]

        fake = _fake_card()

        mock_engine_cls = MagicMock()
        mock_engine_instance = MagicMock()
        mock_engine_instance.generate = AsyncMock(return_value=fake)
        mock_engine_cls.return_value = mock_engine_instance

        mock_cred_instance = MagicMock()
        mock_cred_instance.close = AsyncMock()

        mock_identity_aio = MagicMock()
        mock_identity_aio.DefaultAzureCredential = MagicMock(
            return_value=mock_cred_instance
        )
        mock_identity_aio.get_bearer_token_provider = MagicMock(
            return_value=lambda: "fake"
        )

        with (
            patch.dict(sys.modules, {"azure.identity.aio": mock_identity_aio}),
            patch(
                "cloudguardiq.ai.remediation_engine.RemediationEngine",
                mock_engine_cls,
            ),
            patch("openai.AsyncAzureOpenAI", MagicMock()),
        ):
            resp = await client.post(
                f"/findings/{finding_id}/generate-remediation"
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["card_id"] == fake.card_id
        assert data["narrative"] == "AI-generated narrative"
        assert data["terraform_fix"] is not None
        assert data["confidence_qualifier"] == "high"
        mock_engine_instance.generate.assert_called_once()

    @pytest.mark.asyncio
    async def test_404_for_unknown_finding(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/findings/nonexistent-id/generate-remediation"
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_503_when_openai_not_configured(
        self,
        client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
        list_resp = await client.get("/findings")
        finding_id = list_resp.json()[0]["finding_id"]
        resp = await client.post(
            f"/findings/{finding_id}/generate-remediation"
        )
        assert resp.status_code == 503