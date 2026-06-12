"""CloudGuardIQ -- AdapterBase abstract class.

AdapterBase is the ONLY interface that touches external cloud APIs.
All cloud provider adapters (Azure, AWS, GCP) must inherit from this class
and implement the required abstract methods.
"""

from __future__ import annotations

import abc
import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cloudguardiq.core.models import ResourceSnapshot

logger = logging.getLogger(__name__)


@dataclass
class CapabilityFlags:
    """Flags indicating which data tiers are available for a given adapter."""

    tier1_available: bool = True
    tier2_available: bool = False
    tier3_available: bool = False
    # True when at least one built-in regulatory Policy initiative
    # (see adapters.azure.azure_policy_compliance_adapter.FRAMEWORK_INITIATIVES) is
    # assigned to the subscription, so Microsoft's authoritative per-control
    # compliance evaluation can be ingested.
    policy_compliance_available: bool = False
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AdapterBase(abc.ABC):
    """Abstract adapter that all cloud provider adapters must implement.

    This is the ONLY interface that touches external cloud APIs.
    """

    # ------------------------------------------------------------------
    # Abstract methods -- every adapter MUST implement these
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def scan(self) -> list[ResourceSnapshot]:
        """Scan the cloud environment and return resource snapshots."""

    @abc.abstractmethod
    async def get_api_contract(self) -> dict[str, Any]:
        """Return the current API contract for self-healing contract monitoring."""

    @abc.abstractmethod
    async def validate_connection(self) -> bool:
        """Validate that the adapter can connect to its cloud provider."""

    # ------------------------------------------------------------------
    # Legacy abstract methods -- kept for backward compatibility
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Concrete helper methods
    # ------------------------------------------------------------------

    def validate_snapshot(self, snapshot: ResourceSnapshot) -> bool:
        """Check that a ResourceSnapshot has all required fields populated."""
        required_str_fields = [
            "subscription_id",
            "resource_group",
            "resource_type",
            "resource_name",
            "region",
        ]
        for field_name in required_str_fields:
            value = getattr(snapshot, field_name, None)
            if not value or not isinstance(value, str) or not value.strip():
                logger.warning(
                    "Snapshot validation failed: missing or empty field '%s'",
                    field_name,
                )
                return False

        if snapshot.data_tier is None:
            logger.warning("Snapshot validation failed: missing data_tier")
            return False

        return True

    @staticmethod
    def build_finding_id(rule_id: str, resource_id: str) -> str:
        """Build a deterministic UUID from a rule ID and resource ID."""
        combined = f"{rule_id}:{resource_id}"
        digest = hashlib.sha256(combined.encode()).hexdigest()
        return str(uuid.UUID(digest[:32]))
