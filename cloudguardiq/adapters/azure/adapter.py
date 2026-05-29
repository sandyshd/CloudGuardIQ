"""CloudGuardIQ -- AzureAdapter: main adapter orchestrating tiered scanning.

AzureAdapter inherits AdapterBase and orchestrates:
  Tier 1: NativeScanner (Resource Graph, 52 rules)
  Tier 2: Defender free CSPM Secure Score enrichment
  Tier 3: Defender paid threat intelligence enrichment
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from azure.core.credentials import TokenCredential
from azure.core.credentials_async import AsyncTokenCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

from cloudguardiq.adapters.base import AdapterBase
from cloudguardiq.adapters.capability_detector import CapabilityDetector
from cloudguardiq.adapters.native_scanner import NativeScanner
from cloudguardiq.core.enums import DataTier
from cloudguardiq.core.models import ResourceSnapshot

if TYPE_CHECKING:
    from cloudguardiq.core.database import CosmosRepository

logger = logging.getLogger(__name__)

# Suppress noisy Azure SDK polymorphic deserialization warnings that surface
# when Defender for Cloud returns alert/assessment payloads without an
# explicit discriminator -- these are informational and expected.
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.ERROR)
logging.getLogger("azure.core.serialization").setLevel(logging.ERROR)


class AzureAdapter(AdapterBase):
    """Azure cloud adapter that orchestrates tiered scanning.

    Args:
        credential: Azure TokenCredential for authentication.
        subscription_id: The Azure subscription ID to scan.
        db: CosmosRepository instance for caching capability flags.
    """

    def __init__(
        self,
        credential: TokenCredential,
        subscription_id: str,
        db: CosmosRepository,
        async_credential: AsyncTokenCredential | None = None,
    ) -> None:
        self._credential = credential
        self._async_credential: AsyncTokenCredential = async_credential or credential  # type: ignore[assignment]
        self._subscription_id = subscription_id
        self._db = db
        self._scanner = NativeScanner(
            credential=credential,
            subscription_id=subscription_id,
        )
        self._capability_detector = CapabilityDetector(
            credential=self._async_credential,
            subscription_id=subscription_id,
            db=db,
        )

    # ------------------------------------------------------------------
    # AdapterBase abstract methods
    # ------------------------------------------------------------------

    async def scan(self) -> list[ResourceSnapshot]:
        """Orchestrate tiered scanning.

        1. Always: NativeScanner (Tier 1 -- Resource Graph only)
        2. If tier2_available: enrich with Defender free CSPM Secure Score
        3. If tier3_available: enrich with Defender paid threat intelligence

        Returns enriched list[ResourceSnapshot] with data_tier set correctly.
        """
        flags = await self._capability_detector.detect()
        logger.info(
            "Capability flags for %s: tier1=%s, tier2=%s, tier3=%s",
            self._subscription_id,
            flags.tier1_available,
            flags.tier2_available,
            flags.tier3_available,
        )

        snapshots = await self._scanner.scan()
        logger.info("Tier 1 scan returned %d snapshots", len(snapshots))

        if flags.tier2_available:
            try:
                snapshots = await self._enrich_with_secure_score(snapshots)
                logger.info("Tier 2 enrichment complete")
            except Exception:
                logger.warning(
                    "Tier 2 enrichment failed for %s -- continuing with Tier 1 data",
                    self._subscription_id,
                    exc_info=True,
                )

        if flags.tier3_available:
            try:
                snapshots = await self._enrich_with_threat_intel(snapshots)
                logger.info("Tier 3 enrichment complete")
            except Exception:
                logger.warning(
                    "Tier 3 enrichment failed for %s -- continuing with existing data",
                    self._subscription_id,
                    exc_info=True,
                )

        return snapshots

    async def get_api_contract(self) -> dict[str, Any]:
        """Return current API response schema fingerprint for self-healing monitor.

        Calls Resource Graph with a small representative query and records
        field names and types.
        """
        try:
            client = ResourceGraphClient(self._credential)
            query = QueryRequest(
                subscriptions=[self._subscription_id],
                query="Resources | take 1",
                options=QueryRequestOptions(result_format="objectArray"),
            )
            response = client.resources(query)
            columns: dict[str, str] = {}
            if response.data:
                row: dict[str, Any] = response.data[0] if isinstance(response.data, list) else {}
                columns = {k: type(v).__name__ for k, v in row.items()}
            return {
                "provider": "azure",
                "endpoint": "resource_graph",
                "schema": columns,
                "total_records": response.total_records,
            }
        except Exception:
            logger.warning("Failed to get API contract", exc_info=True)
            return {"provider": "azure", "endpoint": "resource_graph", "schema": {}}

    async def validate_connection(self) -> bool:
        """Quick check: can we call Resource Graph? Returns True/False."""
        try:
            client = ResourceGraphClient(self._credential)
            query = QueryRequest(
                subscriptions=[self._subscription_id],
                query="Resources | take 1",
                options=QueryRequestOptions(result_format="objectArray"),
            )
            client.resources(query)
            return True
        except Exception:
            logger.warning(
                "Connection validation failed for %s",
                self._subscription_id,
                exc_info=True,
            )
            return False

    async def list_resources(self, subscription_id: str) -> list[ResourceSnapshot]:
        """List all resources in the given subscription."""
        scanner = NativeScanner(
            credential=self._credential,
            subscription_id=subscription_id,
        )
        return await scanner.scan()

    async def get_resource(self, resource_id: str) -> ResourceSnapshot | None:
        """Get a single resource by its Azure resource ID."""
        return None

    async def get_cost(self, resource_id: str) -> float:
        """Return estimated monthly cost for a resource."""
        return 0.0

    async def enrich_with_defender(
        self, snapshots: list[ResourceSnapshot]
    ) -> list[ResourceSnapshot]:
        """Enrich snapshots with Defender for Cloud data (best-effort)."""
        flags = await self._capability_detector.detect()
        if flags.tier2_available:
            try:
                snapshots = await self._enrich_with_secure_score(snapshots)
            except Exception:
                logger.warning("Defender enrichment failed", exc_info=True)
        return snapshots

    async def get_raw_properties(self, resource_id: str) -> dict[str, Any]:
        """Fetch raw provider-specific properties for a resource."""
        return {}

    # ------------------------------------------------------------------
    # Tier 2 & 3 enrichment helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_arm_resource_key(arm_id: str) -> str | None:
        """Extract a normalised (rg/name) lookup key from an ARM resource ID."""
        parts = arm_id.lower().split("/")
        try:
            rg_idx = parts.index("resourcegroups")
            rg = parts[rg_idx + 1]
            name = parts[-1]
            return f"{rg}/{name}"
        except (ValueError, IndexError):
            return None

    async def _enrich_with_secure_score(
        self, snapshots: list[ResourceSnapshot]
    ) -> list[ResourceSnapshot]:
        """Tier 2 enrichment: Defender free CSPM Secure Score.

        Fetches recommendations from Defender for Cloud assessments API.
        Extracts the ARM resource ID from rec.id (before /providers/Microsoft.Security/).
        Matches to snapshots by resource_group/resource_name key.
        Upgrades data_tier to TIER2_FREE_CSPM on enriched snapshots.
        Returns original snapshots if anything fails.
        """
        try:
            from azure.mgmt.security.aio import SecurityCenter

            client = SecurityCenter(
                credential=self._async_credential,
                subscription_id=self._subscription_id,
            )
            try:
                recommendations: dict[str, list[dict[str, Any]]] = {}
                async for rec in client.assessments.list(
                    scope=f"/subscriptions/{self._subscription_id}"
                ):
                    rec_id = getattr(rec, "id", "") or ""
                    sec_split = rec_id.split("/providers/Microsoft.Security/")
                    arm_resource = sec_split[0] if len(sec_split) > 1 else ""
                    key = self._extract_arm_resource_key(arm_resource)
                    if key:
                        status = getattr(rec, "status", None)
                        rec_entry = {
                            "display_name": getattr(rec, "display_name", ""),
                            "status": str(getattr(status, "code", "")) if status else "",
                            "arm_resource_id": arm_resource,
                        }
                        recommendations.setdefault(key, []).append(rec_entry)

                snapshot_lookup: dict[str, ResourceSnapshot] = {}
                for snapshot in snapshots:
                    s_key = f"{snapshot.resource_group.lower()}/{snapshot.resource_name.lower()}"
                    snapshot_lookup[s_key] = snapshot

                matched = 0
                for s_key, snapshot in snapshot_lookup.items():
                    if s_key in recommendations:
                        snapshot.config.setdefault(
                            "defender_recommendations", []
                        ).extend(recommendations[s_key])
                        snapshot.data_tier = DataTier.TIER2_FREE_CSPM
                        matched += 1

                logger.info(
                    "Tier 2: %d Defender recommendations mapped to %d/%d snapshots",
                    sum(len(v) for v in recommendations.values()),
                    matched,
                    len(snapshots),
                )
            finally:
                await client.close()  # type: ignore[no-untyped-call]
        except Exception:
            logger.warning(
                "Secure score enrichment failed for %s",
                self._subscription_id,
                exc_info=True,
            )
        return snapshots

    async def _enrich_with_threat_intel(
        self, snapshots: list[ResourceSnapshot]
    ) -> list[ResourceSnapshot]:
        """Tier 3 enrichment: Defender paid threat intelligence.

        Fetches Defender alerts and vulnerability assessments.
        Adds threat intelligence context to config dict of matching snapshots.
        Upgrades data_tier to TIER3_PAID on enriched snapshots.
        Returns original snapshots if anything fails.
        """
        try:
            from azure.mgmt.security.aio import SecurityCenter

            client = SecurityCenter(
                credential=self._async_credential,
                subscription_id=self._subscription_id,
            )
            try:
                alerts_by_resource: dict[str, list[dict[str, Any]]] = {}
                async for alert in client.alerts.list():
                    compromised = getattr(alert, "compromised_entity", "")
                    if compromised:
                        alert_entry = {
                            "alert_type": getattr(alert, "alert_type", ""),
                            "severity": str(getattr(alert, "severity", "")),
                            "description": getattr(alert, "description", ""),
                        }
                        alerts_by_resource.setdefault(
                            compromised.lower(), []
                        ).append(alert_entry)

                matched = 0
                for snapshot in snapshots:
                    resource_key = snapshot.resource_name.lower()
                    if resource_key in alerts_by_resource:
                        snapshot.config.setdefault(
                            "defender_alerts", []
                        ).extend(alerts_by_resource[resource_key])
                        snapshot.data_tier = DataTier.TIER3_PAID
                        matched += 1

                logger.info(
                    "Tier 3: %d alerts mapped to %d/%d snapshots",
                    sum(len(v) for v in alerts_by_resource.values()),
                    matched,
                    len(snapshots),
                )
            finally:
                await client.close()  # type: ignore[no-untyped-call]
        except Exception:
            logger.warning(
                "Threat intelligence enrichment failed for %s",
                self._subscription_id,
                exc_info=True,
            )
        return snapshots
