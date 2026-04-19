"""Tests for CapabilityDetector."""

from __future__ import annotations

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
        detector = CapabilityDetector()
        caps = await detector.detect("sub-123")
        assert DataTier.TIER1_NATIVE in caps.available_tiers
