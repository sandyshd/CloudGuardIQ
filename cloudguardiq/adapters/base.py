"""CloudGuardIQ — Abstract base class for cloud provider adapters."""

from __future__ import annotations

import abc
from typing import Any

from cloudguardiq.core.models import ResourceSnapshot


class AdapterBase(abc.ABC):
    """Abstract adapter that all cloud provider adapters must implement.

    This is the ONLY interface that touches external cloud APIs.
    """

    @abc.abstractmethod
    async def list_resources(self, subscription_id: str) -> list[ResourceSnapshot]:
        """List all resources in the given subscription."""

    @abc.abstractmethod
    async def get_resource(self, resource_id: str) -> ResourceSnapshot | None:
        """Get a single resource by its Azure resource ID."""

    @abc.abstractmethod
    async def get_cost(self, resource_id: str) -> float:
        """Return estimated monthly cost for a resource."""

    @abc.abstractmethod
    async def enrich_with_defender(
        self, snapshots: list[ResourceSnapshot]
    ) -> list[ResourceSnapshot]:
        """Enrich snapshots with Defender for Cloud data (best-effort)."""

    @abc.abstractmethod
    async def get_raw_properties(self, resource_id: str) -> dict[str, Any]:
        """Fetch raw provider-specific properties for a resource."""
