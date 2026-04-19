"""Tests for CapabilityDetector (legacy SubscriptionCapabilities tests)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from cloudguardiq.adapters.capability_detector import CapabilityDetector, SubscriptionCapabilities
from cloudguardiq.core.enums import DataTier


class TestSubscriptionCapabilities:
    def test_default_max_tier(self) -> None:
        caps = SubscriptionCapabilities()
        assert caps.max_tier == DataTier.TIER1_NATIVE

    def test_max_tier_with_defender(self) -> None:
        caps = SubscriptionCapabilities(
            has_defender=True,
            available_tiers=[DataTier.TIER1_NATIVE, DataTier.TIER3_PAID],
        )
        assert caps.max_tier == DataTier.TIER3_PAID

    def test_max_tier_with_cost_management(self) -> None:
        caps = SubscriptionCapabilities(
            has_cost_management=True,
            available_tiers=[DataTier.TIER1_NATIVE, DataTier.TIER2_FREE_CSPM],
        )
        assert caps.max_tier == DataTier.TIER2_FREE_CSPM


class TestCapabilityDetector:
    @pytest.mark.asyncio
    async def test_detect_baseline(self) -> None:
        mock_db = AsyncMock()
        mock_db.get_capability_flags = AsyncMock(return_value=None)
        mock_db.save_capability_flags = AsyncMock()
        detector = CapabilityDetector(
            credential=MagicMock(),
            subscription_id="sub-123",
            db=mock_db,
        )
        # Patch tier2/tier3 to avoid real Azure calls
        detector._probe_tier2 = AsyncMock(return_value=False)  # type: ignore[method-assign]
        detector._probe_tier3 = AsyncMock(return_value=False)  # type: ignore[method-assign]
        flags = await detector.detect()
        assert flags.tier1_available is True
