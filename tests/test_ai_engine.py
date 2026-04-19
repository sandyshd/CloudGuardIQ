"""Tests for AI RemediationEngine."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from cloudguardiq.ai.remediation_engine import AIEngineError, RemediationEngine
from cloudguardiq.core.enums import FindingCategory, RemediationStatus, Severity
from cloudguardiq.core.models import FindingResult


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
            MagicMock(
                message=MagicMock(
                    content='{"summary":"Enable HTTPS","explanation":"Set HTTPS only","risk_if_ignored":"Data in transit exposed","terraform_code":"resource \\"azurerm\\" {}","manual_steps":["Go to portal","Enable HTTPS"]}'
                )
            )
        ]
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        engine = RemediationEngine(client=mock_client)
        card = await engine.generate(sample_finding)

        assert card.summary == "Enable HTTPS"
        assert card.status == RemediationStatus.PENDING
        assert card.finding_id == sample_finding.id
        assert len(card.manual_steps) == 2

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
            MagicMock(
                message=MagicMock(
                    content='{"summary":"Fix","explanation":"Do it","risk_if_ignored":"Bad","terraform_code":"","manual_steps":[]}'
                )
            )
        ]
        mock_client.chat.completions.create = AsyncMock(
            side_effect=[RuntimeError("fail"), mock_response]
        )
        engine = RemediationEngine(client=mock_client)
        card = await engine.generate(sample_finding)
        assert card.summary == "Fix"
