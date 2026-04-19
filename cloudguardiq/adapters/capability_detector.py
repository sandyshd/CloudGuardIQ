"""CloudGuardIQ -- Capability detector for Azure subscription tiers.

Detects which Azure data tiers are available for a given subscription.
Results are cached in Cosmos DB with a 24-hour TTL to avoid probing on every scan.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from cloudguardiq.adapters.base import CapabilityFlags
from cloudguardiq.core.enums import DataTier

if TYPE_CHECKING:
    from azure.core.credentials_async import AsyncTokenCredential

    from cloudguardiq.core.database import CosmosRepository

logger = logging.getLogger(__name__)

CACHE_TTL = timedelta(hours=24)


@dataclass
class SubscriptionCapabilities:
    """Detected capabilities for an Azure subscription."""

    has_defender: bool = False
    has_cost_management: bool = False
    available_tiers: list[DataTier] = field(
        default_factory=lambda: [DataTier.TIER1_NATIVE]
    )

    @property
    def max_tier(self) -> DataTier:
        """Return the highest available data tier."""
        if DataTier.TIER3_PAID in self.available_tiers:
            return DataTier.TIER3_PAID
        if DataTier.TIER2_FREE_CSPM in self.available_tiers:
            return DataTier.TIER2_FREE_CSPM
        return DataTier.TIER1_NATIVE


class CapabilityDetector:
    """Detects which Azure services are available for a subscription.

    Uses Cosmos DB to cache results with a 24-hour TTL.
    """

    def __init__(
        self,
        credential: AsyncTokenCredential,
        subscription_id: str,
        db: CosmosRepository,
    ) -> None:
        self._credential = credential
        self._subscription_id = subscription_id
        self._db = db

    async def detect(self) -> CapabilityFlags:
        """Detect available data tiers for the subscription.

        Checks Cosmos DB cache first. If the cache is fresh (< 24 h),
        returns the cached flags. Otherwise probes all three tiers in
        parallel, saves the result, and returns it.
        """
        cached = await self._db.get_capability_flags(self._subscription_id)
        if cached is not None:
            age = datetime.now(timezone.utc) - cached.detected_at
            if age < CACHE_TTL:
                logger.debug(
                    "Using cached capability flags for %s (age=%s)",
                    self._subscription_id,
                    age,
                )
                return cached

        t1, t2, t3 = await asyncio.gather(
            self._probe_tier1(),
            self._probe_tier2(),
            self._probe_tier3(),
        )

        flags = CapabilityFlags(
            tier1_available=t1,
            tier2_available=t2,
            tier3_available=t3,
            detected_at=datetime.now(timezone.utc),
        )
        await self._db.save_capability_flags(self._subscription_id, flags)
        return flags

    async def _probe_tier1(self) -> bool:
        """Probe Tier 1 availability.

        Tier 1 (Resource Graph + Cost Management) is always available
        to any service principal with Reader role.
        """
        return True

    async def _probe_tier2(self) -> bool:
        """Probe Tier 2 availability (Defender free CSPM).

        Calls SecureScores.list() to check whether Defender free tier
        is active for the subscription.
        """
        try:
            from azure.mgmt.security.aio import SecurityCenter

            client = SecurityCenter(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
            try:
                async for _ in client.secure_scores.list():
                    break
                return True
            finally:
                await client.close()  # type: ignore[no-untyped-call]
        except Exception as exc:
            _status = getattr(exc, "status_code", None)
            if _status in (403, 404):
                logger.info(
                    "Tier 2 not available for %s (HTTP %s)",
                    self._subscription_id,
                    _status,
                )
            else:
                logger.warning(
                    "Tier 2 probe failed for %s: %s",
                    self._subscription_id,
                    exc,
                )
            return False

    async def _probe_tier3(self) -> bool:
        """Probe Tier 3 availability (paid Defender plans).

        Calls Alerts.list() to check whether a paid Defender plan
        is active for the subscription.
        """
        try:
            from azure.mgmt.security.aio import SecurityCenter

            client = SecurityCenter(
                credential=self._credential,
                subscription_id=self._subscription_id,
            )
            try:
                async for _ in client.alerts.list():
                    break
                return True
            finally:
                await client.close()  # type: ignore[no-untyped-call]
        except Exception as exc:
            _status = getattr(exc, "status_code", None)
            if _status == 403:
                logger.info(
                    "Tier 3 not available for %s (HTTP 403)",
                    self._subscription_id,
                )
            else:
                logger.warning(
                    "Tier 3 probe failed for %s: %s",
                    self._subscription_id,
                    exc,
                )
            return False
