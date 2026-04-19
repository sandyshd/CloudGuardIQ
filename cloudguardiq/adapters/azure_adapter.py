"""CloudGuardIQ — Azure adapter implementation."""

from __future__ import annotations

import logging
from typing import Any

from cloudguardiq.adapters.base import AdapterBase
from cloudguardiq.core.enums import DataTier
from cloudguardiq.core.models import ResourceSnapshot

logger = logging.getLogger(__name__)


class AzureAdapter(AdapterBase):
    """Azure cloud provider adapter.

    Uses Azure Resource Manager (ARM) as the baseline data source.
    Enriches with Defender for Cloud when available (graceful degradation).
    """

    def __init__(self, credential: Any = None) -> None:
        self._credential = credential

    async def list_resources(self, subscription_id: str) -> list[ResourceSnapshot]:
        """List all resources in the given Azure subscription via ARM."""
        # Real implementation would use azure.mgmt.resource
        logger.info("Listing resources for subscription %s", subscription_id)
        return []

    async def get_resource(self, resource_id: str) -> ResourceSnapshot | None:
        """Get a single resource by its Azure resource ID."""
        logger.info("Getting resource %s", resource_id)
        return None

    async def get_cost(self, resource_id: str) -> float:
        """Return estimated monthly cost for a resource via Cost Management API."""
        try:
            # Real implementation would use azure.mgmt.costmanagement
            logger.info("Getting cost for %s", resource_id)
            return 0.0
        except Exception:
            logger.warning("Cost Management API failed for %s — returning 0.0", resource_id)
            return 0.0

    async def enrich_with_defender(
        self, snapshots: list[ResourceSnapshot]
    ) -> list[ResourceSnapshot]:
        """Enrich snapshots with Defender for Cloud data.

        This is best-effort — failures are logged and snapshots returned as-is.
        """
        try:
            # Real implementation would use azure.mgmt.security
            logger.info("Enriching %d snapshots with Defender data", len(snapshots))
            for snap in snapshots:
                if snap.data_tier == DataTier.TIER1_NATIVE:
                    snap.data_tier = DataTier.TIER2_FREE_CSPM
        except Exception:
            logger.warning("Defender for Cloud enrichment failed — continuing without it")
        return snapshots

    async def get_raw_properties(self, resource_id: str) -> dict[str, Any]:
        """Fetch raw ARM properties for a resource."""
        logger.info("Getting raw properties for %s", resource_id)
        return {}
