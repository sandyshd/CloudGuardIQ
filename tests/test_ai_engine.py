"""Tests for AI RemediationEngine (legacy test suite)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from cloudguardiq.ai.remediation_engine import AIEngineError, RemediationEngine
from cloudguardiq.core.enums import FindingCategory, RemediationStatus, Severity
from cloudguardiq.core.models import FindingResult


def _valid_response_content() -> str:
    return (
        '{"narrative":"Enable HTTPS","business_risk":"Data in transit exposed",'
        '"terraform_fix":"resource \\"azurerm\\" {}",'
        '"cli_fix":"az storage account update --https-only true",'
        '"confidence_qualifier":"Based on configuration scan",'
        '"estimated_savings_usd":0.0}'
    )


@pytest.fixture
def sample_finding() -> FindingResult:
    return FindingResult(
        snapshot_id=uuid4(),
        rule_id="STORAGE_HTTPS_ONLY",
        title="Storage allows HTTP",
        description="Storage account allows HTTP traffic",
        severity=Severity.HIGH,
        category=FindingCategory.SECURITY,
        resource_id="rid",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="sa1",
    )


class TestRemediationEngine:
    @pytest.mark.asyncio
    async def test_generate_success(self, sample_finding: FindingResult) -> None:
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content=_valid_response_content()))
        ]
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        engine = RemediationEngine(client=mock_client)
        card = await engine.generate(sample_finding)

        assert card.narrative == "Enable HTTPS"
        assert card.status == RemediationStatus.PENDING

    @pytest.mark.asyncio
    async def test_generate_no_client(self, sample_finding: FindingResult) -> None:
        engine = RemediationEngine(client=None)
        with pytest.raises(AIEngineError, match="OpenAI client not configured"):
            await engine.generate(sample_finding)

    @pytest.mark.asyncio
    async def test_generate_retries_on_failure(self, sample_finding: FindingResult) -> None:
        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(
            side_effect=[
                RuntimeError("timeout"),
                RuntimeError("timeout"),
                RuntimeError("timeout"),
            ]
        )
        engine = RemediationEngine(client=mock_client)
        with pytest.raises(AIEngineError):
            await engine.generate(sample_finding)
        assert mock_client.chat.completions.create.call_count == 3

    @pytest.mark.asyncio
    async def test_generate_succeeds_on_retry(self, sample_finding: FindingResult) -> None:
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content=_valid_response_content()))
        ]
        mock_client.chat.completions.create = AsyncMock(
            side_effect=[RuntimeError("fail"), mock_response]
        )
        engine = RemediationEngine(client=mock_client)
        card = await engine.generate(sample_finding)
        assert card.narrative == "Enable HTTPS"
