"""CloudGuardIQ — Capability detector for Azure subscription tiers."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from cloudguardiq.core.enums import DataTier

logger = logging.getLogger(__name__)


@dataclass
class SubscriptionCapabilities:
    """Detected capabilities for an Azure subscription."""

    has_defender: bool = False
    has_cost_management: bool = False
    available_tiers: list[DataTier] = field(default_factory=lambda: [DataTier.TIER1_NATIVE])

    @property
    def max_tier(self) -> DataTier:
        """Return the highest available data tier."""
        if DataTier.TIER3_PAID in self.available_tiers:
            return DataTier.TIER3_PAID
        if DataTier.TIER2_FREE_CSPM in self.available_tiers:
            return DataTier.TIER2_FREE_CSPM
        return DataTier.TIER1_NATIVE


class CapabilityDetector:
    """Detects which Azure services are available for a subscription."""

    async def detect(self, subscription_id: str) -> SubscriptionCapabilities:
        """Probe the subscription to determine available data tiers.

        Always returns at least TIER1_NATIVE (ARM-only scanning).
        """
        caps = SubscriptionCapabilities()

        # Try Defender for Cloud
        try:
            caps.has_defender = await self._check_defender(subscription_id)
            if caps.has_defender:
                caps.available_tiers.append(DataTier.TIER3_PAID)
        except Exception:
            logger.warning(
                "Defender for Cloud check failed for %s — continuing without it",
                subscription_id,
            )

        # Try Cost Management
        try:
            caps.has_cost_management = await self._check_cost_management(subscription_id)
            if caps.has_cost_management and DataTier.TIER2_FREE_CSPM not in caps.available_tiers:
                caps.available_tiers.append(DataTier.TIER2_FREE_CSPM)
        except Exception:
            logger.warning(
                "Cost Management check failed for %s — continuing without it",
                subscription_id,
            )

        return caps

    async def _check_defender(self, subscription_id: str) -> bool:
        """Check if Defender for Cloud is enabled."""
        # Placeholder — real implementation in AzureAdapter
        _ = subscription_id
        return False

    async def _check_cost_management(self, subscription_id: str) -> bool:
        """Check if Cost Management is accessible."""
        _ = subscription_id
        return False
