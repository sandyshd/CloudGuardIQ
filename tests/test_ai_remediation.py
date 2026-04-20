"""Tests for AI remediation engine, prompt templates, and risk scorer."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from cloudguardiq.ai.prompt_templates import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from cloudguardiq.ai.remediation_engine import AIEngineError, RemediationEngine
from cloudguardiq.ai.risk_scorer import compute_risk_score
from cloudguardiq.core.enums import DataTier, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_snapshot(
    data_tier: DataTier = DataTier.TIER1_NATIVE,
    cost_monthly: float = 50.0,
) -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id="sub-test-123",
        resource_group="rg-test",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="satest1",
        region="eastus",
        data_tier=data_tier,
        cost_monthly=cost_monthly,
    )


def _make_finding(
    severity: Severity = Severity.HIGH,
    data_tier: DataTier = DataTier.TIER1_NATIVE,
    cost_monthly: float = 50.0,
    compliance_frameworks: list[str] | None = None,
    waste_monthly_usd: float = 0.0,
) -> FindingResult:
    snap = _make_snapshot(data_tier=data_tier, cost_monthly=cost_monthly)
    return FindingResult(
        rule_id="STORAGE_HTTPS_ONLY",
        rule_name="Storage allows HTTP",
        severity=severity,
        description="Storage account allows HTTP traffic",
        resource_snapshot=snap,
        compliance_frameworks=compliance_frameworks or [],
        waste_monthly_usd=waste_monthly_usd,
    )


def _valid_openai_response() -> dict:
    return {
        "narrative": "Storage account allows unencrypted HTTP traffic.",
        "business_risk": "Data in transit may be intercepted.",
        "terraform_fix": 'resource "azurerm_storage_account" "fix" {}',
        "cli_fix": "az storage account update --https-only true",
        "confidence_qualifier": "Based on configuration scan -- threat exploitation not confirmed.",
        "estimated_savings_usd": 0.0,
    }


def _mock_openai_response(data: dict) -> MagicMock:
    resp = MagicMock()
    resp.choices = [MagicMock(message=MagicMock(content=json.dumps(data)))]
    return resp


@pytest.fixture
def finding() -> FindingResult:
    return _make_finding()


@pytest.fixture
def mock_client() -> MagicMock:
    client = MagicMock()
    client.chat.completions.create = AsyncMock(
        return_value=_mock_openai_response(_valid_openai_response())
    )
    return client


@pytest.fixture
def mock_db() -> MagicMock:
    db = MagicMock()
    db.save_remediation_card = AsyncMock(return_value="card-id-123")
    return db


# ---------------------------------------------------------------------------
# RemediationEngine.generate
# ---------------------------------------------------------------------------


class TestGenerate:
    @pytest.mark.asyncio
    async def test_generate_returns_remediation_card(
        self, finding: FindingResult, mock_client: MagicMock, mock_db: MagicMock
    ) -> None:
        engine = RemediationEngine(client=mock_client, deployment="gpt-4o", db=mock_db)
        card = await engine.generate(finding)

        assert card.narrative == "Storage account allows unencrypted HTTP traffic."
        assert card.terraform_fix != ""
        assert card.cli_fix != ""
        assert card.confidence_qualifier != ""
        assert card.model_version == "gpt-4o"
        assert card.finding_result == finding
        mock_db.save_remediation_card.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_generate_retries_on_bad_json(
        self, finding: FindingResult
    ) -> None:
        client = MagicMock()
        # First call returns invalid JSON, second returns valid
        bad_resp = MagicMock()
        bad_resp.choices = [MagicMock(message=MagicMock(content="not json at all"))]
        good_resp = _mock_openai_response(_valid_openai_response())

        client.chat.completions.create = AsyncMock(
            side_effect=[bad_resp, good_resp]
        )
        engine = RemediationEngine(client=client)
        card = await engine.generate(finding)

        assert card.narrative != ""
        assert client.chat.completions.create.call_count == 2

    @pytest.mark.asyncio
    async def test_generate_raises_after_max_retries(
        self, finding: FindingResult
    ) -> None:
        client = MagicMock()
        bad_resp = MagicMock()
        bad_resp.choices = [MagicMock(message=MagicMock(content="invalid"))]
        client.chat.completions.create = AsyncMock(
            return_value=bad_resp,
        )
        engine = RemediationEngine(client=client)
        with pytest.raises(AIEngineError, match="failed after 3 retries"):
            await engine.generate(finding)


# ---------------------------------------------------------------------------
# RemediationEngine.generate_batch
# ---------------------------------------------------------------------------


class TestGenerateBatch:
    @pytest.mark.asyncio
    async def test_generate_batch_respects_concurrency_limit(
        self, mock_client: MagicMock
    ) -> None:
        findings = [_make_finding() for _ in range(10)]
        engine = RemediationEngine(client=mock_client)

        # Track concurrent calls via a counter
        max_concurrent_seen = 0
        current_concurrent = 0
        lock = asyncio.Lock()

        original_generate = engine.generate

        async def tracked_generate(f: FindingResult) -> object:
            nonlocal max_concurrent_seen, current_concurrent
            async with lock:
                current_concurrent += 1
                if current_concurrent > max_concurrent_seen:
                    max_concurrent_seen = current_concurrent
            try:
                return await original_generate(f)
            finally:
                async with lock:
                    current_concurrent -= 1

        engine.generate = tracked_generate  # type: ignore[assignment]
        cards = await engine.generate_batch(findings, max_concurrent=5)

        assert len(cards) == 10
        assert max_concurrent_seen <= 5


# ---------------------------------------------------------------------------
# Prompt template checks
# ---------------------------------------------------------------------------


class TestPromptTemplates:
    def test_prompt_includes_data_tier(self) -> None:
        tier1_finding = _make_finding(data_tier=DataTier.TIER1_NATIVE)
        tier3_finding = _make_finding(data_tier=DataTier.TIER3_PAID)

        snap1 = tier1_finding.resource_snapshot
        snap3 = tier3_finding.resource_snapshot
        assert snap1 is not None
        assert snap3 is not None

        prompt1 = USER_PROMPT_TEMPLATE.format(
            finding_json="{}",
            subscription_id=snap1.subscription_id,
            resource_group=snap1.resource_group,
            resource_name=snap1.resource_name,
            resource_type=snap1.resource_type,
            cost_monthly=f"{snap1.cost_monthly:.2f}",
            data_tier=snap1.data_tier.value,
            compliance_frameworks="None",
        )
        prompt3 = USER_PROMPT_TEMPLATE.format(
            finding_json="{}",
            subscription_id=snap3.subscription_id,
            resource_group=snap3.resource_group,
            resource_name=snap3.resource_name,
            resource_type=snap3.resource_type,
            cost_monthly=f"{snap3.cost_monthly:.2f}",
            data_tier=snap3.data_tier.value,
            compliance_frameworks="None",
        )

        assert "TIER1_NATIVE" in prompt1
        assert "TIER3_PAID" in prompt3
        assert "TIER3_PAID" not in prompt1

    def test_system_prompt_contains_tier_qualifiers(self) -> None:
        assert "threat exploitation not confirmed" in SYSTEM_PROMPT
        assert "security posture assessment" in SYSTEM_PROMPT
        assert "threat intelligence" in SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Risk scorer
# ---------------------------------------------------------------------------


class TestRiskScorer:
    def test_risk_scorer_critical_high_cost(self) -> None:
        finding = _make_finding(
            severity=Severity.CRITICAL,
            waste_monthly_usd=200.0,
            compliance_frameworks=["CIS", "NIST", "SOC2", "PCI-DSS"],
        )
        score = compute_risk_score(finding)
        # alpha*100 + beta*100 + gamma*100 = 50+30+20 = 100
        assert score >= 95.0
        assert score <= 100.0

    def test_risk_scorer_low_severity_no_cost(self) -> None:
        finding = _make_finding(
            severity=Severity.LOW,
            waste_monthly_usd=0.0,
            compliance_frameworks=[],
        )
        score = compute_risk_score(finding)
        # alpha*40 + beta*0 + gamma*0 = 20
        assert score == 20.0

    def test_risk_scorer_medium_with_one_framework(self) -> None:
        finding = _make_finding(
            severity=Severity.MEDIUM,
            waste_monthly_usd=50.0,
            compliance_frameworks=["CIS"],
        )
        score = compute_risk_score(finding)
        # alpha*60 + beta*50 + gamma*25 = 30+15+5 = 50
        assert score == 50.0

    def test_risk_scorer_returns_float(self) -> None:
        finding = _make_finding()
        score = compute_risk_score(finding)
        assert isinstance(score, float)
        assert 0.0 <= score <= 100.0
