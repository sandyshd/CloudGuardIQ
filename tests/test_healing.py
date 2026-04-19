"""Tests for healing module."""

from __future__ import annotations

from uuid import uuid4

import pytest

from cloudguardiq.core.enums import CloudProvider, DataTier, FindingCategory, Severity
from cloudguardiq.core.models import FindingResult, RemediationCard, ResourceSnapshot
from cloudguardiq.healing.contract_monitor import ContractMonitor
from cloudguardiq.healing.drift_detector import DriftDetector
from cloudguardiq.healing.repair_agent import RepairAgent


class TestContractMonitor:
    @pytest.mark.asyncio
    async def test_valid_contract(self) -> None:
        monitor = ContractMonitor()
        assert await monitor.check_contract("test", {"key": "value"}) is True

    @pytest.mark.asyncio
    async def test_invalid_contract(self) -> None:
        monitor = ContractMonitor()
        assert await monitor.check_contract("test", "not a dict") is False  # type: ignore[arg-type]


class TestDriftDetector:
    @pytest.mark.asyncio
    async def test_detect_drift(self) -> None:
        expected = ResourceSnapshot(
            subscription_id="sub-1",
            resource_group="rg",
            resource_type="t",
            resource_name="n",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
            config={"key": "expected_value"},
        )
        actual = ResourceSnapshot(
            subscription_id="sub-1",
            resource_group="rg",
            resource_type="t",
            resource_name="n",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
            config={"key": "actual_value"},
        )
        detector = DriftDetector()
        diffs = await detector.detect_drift(expected, actual)
        assert "key" in diffs
        assert diffs["key"] == ("expected_value", "actual_value")

    @pytest.mark.asyncio
    async def test_no_drift(self) -> None:
        snap = ResourceSnapshot(
            subscription_id="sub-1",
            resource_group="rg",
            resource_type="t",
            resource_name="n",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
            config={"key": "same"},
        )
        detector = DriftDetector()
        diffs = await detector.detect_drift(snap, snap)
        assert diffs == {}


class TestRepairAgent:
    @pytest.mark.asyncio
    async def test_execute_repair_stub(self) -> None:
        finding = FindingResult(
            snapshot_id=uuid4(),
            rule_id="TEST",
            title="T",
            description="D",
            severity=Severity.LOW,
            category=FindingCategory.SECURITY,
            resource_id="r",
            resource_type="t",
            resource_name="n",
        )
        card = RemediationCard(
            finding_id=finding.id,
            summary="Fix",
            explanation="Do it",
        )
        agent = RepairAgent()
        result = await agent.execute_repair(finding, card)
        assert result is False
