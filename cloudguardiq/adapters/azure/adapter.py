"""CloudGuardIQ -- AzureAdapter: main adapter orchestrating tiered scanning.

AzureAdapter inherits AdapterBase and orchestrates:
  Tier 1: NativeScanner (Resource Graph, 52 rules)
  Tier 2: Defender free CSPM Secure Score enrichment
  Tier 3: Defender paid threat intelligence enrichment
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING, Any

from azure.core.credentials import TokenCredential
from azure.core.credentials_async import AsyncTokenCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

from cloudguardiq.adapters.azure.azure_policy_compliance_adapter import (
    AzurePolicyComplianceAdapter,
)
from cloudguardiq.adapters.azure.microsoft_graph_iam_adapter import (
    MicrosoftGraphIamAdapter,
)
from cloudguardiq.adapters.base import AdapterBase, CapabilityFlags
from cloudguardiq.adapters.capability_detector import CapabilityDetector
from cloudguardiq.adapters.native_scanner import NativeScanner
from cloudguardiq.adapters.recommenders.azure import AzureRecommenderProvider
from cloudguardiq.core.enums import (
    CloudProvider,
    DataTier,
    FindingType,
    Severity,
)
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

if TYPE_CHECKING:
    from cloudguardiq.core.database import CosmosRepository

logger = logging.getLogger(__name__)

# Suppress noisy Azure SDK polymorphic deserialization warnings that surface
# when Defender for Cloud returns alert/assessment payloads without an
# explicit discriminator -- these are informational and expected.
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.ERROR)
logging.getLogger("azure.core.serialization").setLevel(logging.ERROR)

#: Maps a Defender for Cloud assessment severity string to our enum.
_DEFENDER_SEVERITY_MAP: dict[str, Severity] = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}

#: Maps a Defender assessment ``name`` to the native rule_id it overlaps.
#: When both fire for the same resource the pipeline prefers the native
#: finding (richer remediation) and drops the Defender duplicate. Defender
#: findings without an entry here are always kept -- uncovered resource
#: types are the whole point of this ingestion. Extend as overlaps are
#: confirmed against real assessment ids.
DEFENDER_TO_NATIVE_RULE: dict[str, str] = {}


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
        # Tier 1 (free, Graph Directory.Read + Reader): enrich role-
        # assignment snapshots with Azure AD identity context (guest/SP
        # detection, MFA baseline, SP secret expiry, classic admins) so
        # the IAM-004..008 rules can evaluate. Best-effort; never raises.
        self._graph_iam_adapter = MicrosoftGraphIamAdapter(
            credential=self._async_credential,
            subscription_id=subscription_id,
        )
        # Tier 1 (free, Reader-accessible): ingest Microsoft's authoritative
        # per-control compliance evaluation from Azure Policy. Emits
        # FindingResult objects directly; the local rules keep running.
        self._policy_adapter = AzurePolicyComplianceAdapter(
            credential=credential,
            subscription_id=subscription_id,
            db=db,
        )
        # Populated by scan(); merged into the pipeline's findings list.
        self._policy_findings: list[FindingResult] = []
        # Populated by scan() when Defender for Cloud is present; merged
        # into the pipeline's findings list alongside policy findings.
        self._defender_findings: list[FindingResult] = []
        # Tier 1 (free, Reader): Azure Advisor cost + reservation /
        # savings-plan recommendations. Normalized to DIRECT FinOps
        # findings and merged through the pipeline's recommender source.
        self._recommender_provider = AzureRecommenderProvider(
            credential, subscription_id,
        )
        self._recommender_findings: list[FindingResult] = []

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

        # Run the Tier 1 Resource Graph scan and the (free, Reader-accessible)
        # Azure Policy regulatory-compliance ingestion concurrently. Policy
        # findings are stashed on the adapter and merged by the pipeline; a
        # Policy failure never blocks the resource scan (fetch_findings never
        # raises -- it returns []).
        snapshots, self._policy_findings = await asyncio.gather(
            self._scanner.scan(),
            self._policy_adapter.fetch_findings(),
        )
        logger.info(
            "Tier 1 scan returned %d snapshots, %d policy finding(s)",
            len(snapshots),
            len(self._policy_findings),
        )

        # Tier 1 identity enrichment: resolve role-assignment principals
        # via Microsoft Graph so IAM-004..008 can evaluate. enrich() never
        # raises -- on failure it returns the snapshots unchanged.
        snapshots = await self._graph_iam_adapter.enrich(snapshots)

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

        # Defender for Cloud assessments as first-class findings. Gated on
        # capability flags inside the method; never raises (returns [] on
        # any failure) so a Defender outage cannot break the scan.
        self._defender_findings = await self.fetch_defender_findings(
            snapshots, flags=flags,
        )
        logger.info(
            "Defender ingestion produced %d finding(s) for %s",
            len(self._defender_findings),
            self._subscription_id,
        )

        # Azure Advisor + benefit recommendations. get_recommendations()
        # never raises (returns [] on any failure) so a recommender
        # outage cannot break the scan or suppress the heuristic rules.
        self._recommender_findings = (
            await self._recommender_provider.get_recommendations(
                f"/subscriptions/{self._subscription_id}"
            )
        )
        logger.info(
            "Recommender ingestion produced %d finding(s) for %s",
            len(self._recommender_findings),
            self._subscription_id,
        )

        return snapshots

    async def fetch_policy_findings(self) -> list[FindingResult]:
        """Ingest Azure Policy regulatory-compliance findings on demand.

        The interactive ``POST /scan`` endpoint builds snapshots via
        ``list_resources()`` rather than ``scan()``, so it does not populate
        ``policy_findings`` automatically. This method runs the (free,
        Reader-accessible) Policy ingestion directly and stashes the result so
        ``policy_findings`` reflects it too. Never raises -- returns ``[]`` on
        any failure or when no regulatory initiative is assigned.
        """
        self._policy_findings = await self._policy_adapter.fetch_findings()
        return self._policy_findings

    @property
    def policy_findings(self) -> list[FindingResult]:
        """Azure Policy compliance findings from the most recent scan().

        The scan pipeline merges these into the rule-engine findings so they
        flow through the scorecard, PDF readiness report, and GPT remediation.
        Empty until scan() has run (or when no regulatory initiative is
        assigned).
        """
        return self._policy_findings

    @property
    def defender_findings(self) -> list[FindingResult]:
        """Defender for Cloud findings from the most recent ``scan()``.

        The scan pipeline merges these into the rule-engine findings,
        preferring a native finding when both describe the same
        (resource, issue) while keeping Defender-only findings for resource
        types that have no native rule. Empty until ``scan()`` has run (or
        when Defender for Cloud is not enabled on the subscription).
        """
        return self._defender_findings

    @property
    def recommender_findings(self) -> list[FindingResult]:
        """Native cost-recommender findings from the most recent scan().

        Advisor / reservation / savings-plan recommendations normalized to
        DIRECT FinOps findings. The scan pipeline merges these through the
        same path as the security sources, superseding the overlapping
        heuristic rule for a resource. Empty until scan() has run.
        """
        return self._recommender_findings

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

    def _security_center_client(self) -> Any:
        """Return an async Defender for Cloud ``SecurityCenter`` client.

        Isolated so tests can substitute a fake client without importing
        the Azure SDK or making network calls. All Defender SDK usage is
        confined to the adapter layer.
        """
        from azure.mgmt.security.aio import SecurityCenter

        return SecurityCenter(
            credential=self._async_credential,
            subscription_id=self._subscription_id,
        )

    async def fetch_defender_findings(
        self,
        snapshots: list[ResourceSnapshot],
        flags: CapabilityFlags | None = None,
    ) -> list[FindingResult]:
        """Ingest Defender for Cloud assessments as first-class findings.

        Maps every ``Unhealthy`` assessment to a :class:`FindingResult` so
        resource types without a native rule still surface real security
        findings. Correlates each assessment to a scanned snapshot by ARM
        resource id; when no snapshot matches (type not in inventory) the
        finding is still emitted against a minimal snapshot built from the
        ARM id. When ``tier3_available`` Defender alerts add deeper signal.

        Gating: returns ``[]`` immediately unless ``tier2_available``.
        Graceful degradation: any Defender failure is logged and yields
        ``[]`` -- a Defender outage never breaks the scan.

        Args:
            snapshots: The Tier 1 inventory used to correlate assessments.
            flags: Pre-detected capability flags; re-detected when omitted.

        Returns:
            Normalised, priority-scored Defender findings (never raw
            payloads).
        """
        if flags is None:
            flags = await self._capability_detector.detect()
        if not flags.tier2_available:
            return []

        lookup: dict[str, ResourceSnapshot] = {
            f"{s.resource_group.lower()}/{s.resource_name.lower()}": s
            for s in snapshots
        }
        findings: list[FindingResult] = []
        try:
            client = self._security_center_client()
        except Exception:
            logger.warning(
                "Defender client init failed for %s -- skipping ingestion",
                self._subscription_id,
                exc_info=True,
            )
            return []
        try:
            scope = f"/subscriptions/{self._subscription_id}"
            async for assessment in client.assessments.list(scope=scope):
                finding = self._assessment_to_finding(assessment, lookup)
                if finding is not None:
                    findings.append(finding)
        except Exception:
            logger.warning(
                "Defender assessment ingestion failed for %s -- "
                "returning no Defender findings",
                self._subscription_id,
                exc_info=True,
            )
            findings = []
        finally:
            with contextlib.suppress(Exception):
                await client.close()
        return findings

    def _assessment_to_finding(
        self,
        assessment: Any,
        lookup: dict[str, ResourceSnapshot],
    ) -> FindingResult | None:
        """Convert one Defender assessment to a FindingResult.

        Returns ``None`` for assessments whose status is not ``Unhealthy``.
        """
        status = getattr(assessment, "status", None)
        code = str(getattr(status, "code", "") or "")
        if code.lower() != "unhealthy":
            return None

        details = getattr(assessment, "resource_details", None)
        arm_id = str(getattr(details, "id", "") or "")
        if not arm_id:
            full_id = str(getattr(assessment, "id", "") or "")
            arm_id = full_id.split("/providers/Microsoft.Security/")[0]

        meta = getattr(assessment, "metadata", None)
        severity_raw = str(getattr(meta, "severity", "") or "")
        severity = _DEFENDER_SEVERITY_MAP.get(
            severity_raw.lower(), Severity.MEDIUM,
        )
        description = (
            str(getattr(meta, "description", "") or "")
            or str(getattr(status, "description", "") or "")
        )
        categories = getattr(meta, "categories", None) or []
        if isinstance(categories, list):
            frameworks = [str(c) for c in categories]
        elif categories:
            frameworks = [str(categories)]
        else:
            frameworks = []

        name = str(getattr(assessment, "name", "") or "")
        display_name = (
            str(getattr(assessment, "display_name", "") or "")
            or str(getattr(meta, "display_name", "") or "")
            or name
        )
        rule_id = f"DEFENDER-{name}"

        key = self._extract_arm_resource_key(arm_id) if arm_id else None
        snapshot = lookup.get(key) if key else None
        if snapshot is not None:
            snapshot.data_tier = DataTier.TIER2_FREE_CSPM
            resource_id = snapshot.id
        else:
            snapshot = (
                self._build_minimal_snapshot(arm_id) if arm_id else None
            )
            resource_id = arm_id or rule_id

        evidence: dict[str, Any] = {
            "assessment_name": name,
            "status": code,
            "arm_resource_id": arm_id,
            "severity": severity_raw,
            "resource_key": key or "",
            "native_rule_overlap": DEFENDER_TO_NATIVE_RULE.get(name, ""),
            "categories": frameworks,
        }
        remediation = str(
            getattr(meta, "remediation_description", "") or ""
        )
        if remediation:
            evidence["remediation"] = remediation

        finding = FindingResult(
            finding_id=AdapterBase.build_finding_id(rule_id, resource_id),
            resource_snapshot=snapshot,
            rule_id=rule_id,
            rule_name=display_name,
            severity=severity,
            finding_type=FindingType.SECURITY,
            description=description,
            evidence=evidence,
            compliance_frameworks=frameworks,
        )
        finding.compute_priority_score()
        return finding

    @staticmethod
    def _build_minimal_snapshot(arm_id: str) -> ResourceSnapshot:
        """Build a minimal snapshot from an ARM resource id.

        Used when a Defender assessment targets a resource type absent from
        the Tier 1 inventory, so the finding still carries resource context
        downstream. ``config`` is left empty -- the full config is not
        needed for security scoring.
        """
        parts = arm_id.lower().split("/")
        subscription_id = ""
        resource_group = ""
        resource_type = "unknown"
        resource_name = arm_id.rstrip("/").split("/")[-1] or "unknown"
        with contextlib.suppress(ValueError, IndexError):
            subscription_id = parts[parts.index("subscriptions") + 1]
        with contextlib.suppress(ValueError, IndexError):
            resource_group = parts[parts.index("resourcegroups") + 1]
        with contextlib.suppress(ValueError, IndexError):
            prov_idx = parts.index("providers")
            resource_type = (
                "/".join(parts[prov_idx + 1 : prov_idx + 3]) or "unknown"
            )
        return ResourceSnapshot(
            id=arm_id,
            provider=CloudProvider.AZURE,
            subscription_id=subscription_id or "unknown",
            resource_group=resource_group or "unknown",
            resource_type=resource_type,
            resource_name=resource_name,
            region="unknown",
            config={},
            data_tier=DataTier.TIER2_FREE_CSPM,
        )

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
