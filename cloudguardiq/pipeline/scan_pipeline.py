"""CloudGuardIQ -- Async scan pipeline."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cloudguardiq.adapters.pricing.live_prices import refresh_prices
from cloudguardiq.billing.plans import UNLIMITED, get_plan
from cloudguardiq.billing.quota import check_ai_quota
from cloudguardiq.billing.repository import BillingRepository
from cloudguardiq.billing.usage import UsageRepository
from cloudguardiq.core.enums import Severity
from cloudguardiq.core.models import FindingResult

logger = logging.getLogger(__name__)


class ScanResult(BaseModel):
    """Summary of a completed scan pipeline run."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subscription_id: str
    resources_scanned: int = 0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    total_waste_usd: float = 0.0
    duration_seconds: float = 0.0
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanPipeline:
    """Orchestrates the full scan pipeline.

    Steps:
      1. adapter.scan() -> list[ResourceSnapshot]
      2. policy_engine.evaluate(snapshots) -> list[FindingResult]
      3. Send each finding to Service Bus queue (decouple AI)
      4. Return ScanResult summary
    """

    def __init__(
        self,
        adapter: Any,
        policy_engine: Any,
        ai_engine: Any,
        db: Any,
        service_bus_sender: Any | None = None,
        *,
        billing_repo: BillingRepository | None = None,
        usage_repo: UsageRepository | None = None,
    ) -> None:
        """Initialise the scan pipeline.

        Args:
            adapter: Cloud adapter with async scan() method.
            policy_engine: PolicyEngine for evaluating snapshots.
            ai_engine: RemediationEngine (not used during scan -- AI is async).
            db: CosmosRepository for persisting scan results.
            service_bus_sender: Azure Service Bus sender for findings queue.
            billing_repo: Billing repository (enables producer-side quota
                awareness; when omitted findings are queued without limits).
            usage_repo: Usage repository (required alongside *billing_repo*).
        """
        self._adapter = adapter
        self._policy_engine = policy_engine
        self._ai_engine = ai_engine
        self._db = db
        self._sender = service_bus_sender
        self._billing_repo = billing_repo
        self._usage_repo = usage_repo

    async def run(self, subscription_id: str, tenant_id: str = "") -> ScanResult:
        """Execute the full scan pipeline.

        Args:
            subscription_id: Azure subscription ID to scan.

        Returns:
            ScanResult with scan summary (no AI results -- they come async).
        """
        start = time.monotonic()
        started_at = datetime.now(timezone.utc)
        scan_id = str(uuid.uuid4())

        logger.info("Scan %s started for subscription %s", scan_id, subscription_id)

        # Refresh pricing cache (no-op if refreshed within the last 24 h)
        try:
            await refresh_prices()
        except Exception as _pricing_exc:  # noqa: BLE001
            logger.warning("Pricing cache refresh failed: %s", _pricing_exc)

        # Step 1: Scan resources
        try:
            snapshots = await self._adapter.scan()
        except Exception as exc:
            logger.error("Adapter scan failed for %s: %s", subscription_id, exc)
            raise

        # Phase 2: stamp tenant on snapshots so isolation holds end-to-end.
        if tenant_id:
            for snap in snapshots:
                snap.tenant_id = tenant_id

        # Step 2: Evaluate policies
        findings = self._policy_engine.evaluate(snapshots)

        # Step 2b: Merge Azure Policy regulatory-compliance findings (Tier 1,
        # free) the adapter emits directly, bypassing the rule registry. The
        # local rules above still run unchanged for FinOps + safety checks.
        policy_findings = getattr(self._adapter, "policy_findings", None)
        if policy_findings:
            findings.extend(policy_findings)
            logger.info(
                "Merged %d Azure Policy compliance finding(s) into scan %s",
                len(policy_findings),
                scan_id,
            )
        if tenant_id:
            for finding in findings:
                finding.tenant_id = tenant_id

        # Defensive guard: ensure priority_score is computed for all findings
        for finding in findings:
            if finding.priority_score == 0.0:
                finding.compute_priority_score()

        # Step 3: Send findings to Service Bus queue, capped by tenant\'s
        # remaining AI quota. Findings are persisted in full (Step 4) -- the
        # cap only applies to the AI generation that the queue triggers.
        # Highest-priority findings are queued first so a capped tenant
        # still gets remediation for the most important issues.
        deferred_count = await self._queue_findings(findings, tenant_id)
        if deferred_count:
            logger.info(
                "Deferred %d finding(s) past tenant=%s AI quota; "
                "raw findings still saved -- upgrade to unlock more",
                deferred_count, tenant_id or "<unknown>",
            )

        # Step 4: Save findings to Cosmos DB (lifecycle-aware merge)
        seen_ids: set[str] = set()
        if self._db is not None:
            logger.info("Saving %d findings to Cosmos DB", len(findings))
            for finding in findings:
                try:
                    await self._db.save_finding(finding, scan_id=scan_id)
                    seen_ids.add(finding.finding_id)
                except Exception as exc:
                    logger.error(
                        "Failed to save finding %s: %s", finding.finding_id, exc,
                        exc_info=True,
                    )
            # Auto-resolve OPEN findings that were not re-detected this scan.
            # Best-effort: a Cosmos hiccup must not fail the timer-driven scan.
            # Only sweep when the scan enumerated resources -- a 0-snapshot
            # scan is degraded (auth/permission/transient failure), not proof
            # that prior findings were remediated, so resolving them would
            # wrongly blank the dashboard.
            if snapshots:
                try:
                    await self._db.mark_unseen_findings_resolved(
                        subscription_id, seen_ids, scan_id,
                        tenant_id=tenant_id or None,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Auto-resolve sweep failed for scan %s: %s",
                        scan_id, exc,
                    )
            else:
                logger.warning(
                    "Scan %s enumerated 0 resources -- skipping auto-resolve "
                    "sweep to preserve existing findings (degraded scan).",
                    scan_id,
                )
        else:
            logger.error("No database connection -- cannot save findings")

        # Build result
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        total_waste = sum(f.waste_monthly_usd for f in findings)
        duration = time.monotonic() - start

        result = ScanResult(
            scan_id=scan_id,
            subscription_id=subscription_id,
            resources_scanned=len(snapshots),
            findings_count=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            total_waste_usd=round(total_waste, 2),
            duration_seconds=round(duration, 3),
            started_at=started_at,
        )

        # Save scan result to Cosmos DB
        if self._db is not None:
            try:
                await self._save_scan_result(result)
            except Exception as exc:
                logger.error("Failed to save scan result %s: %s", scan_id, exc, exc_info=True)

        logger.info(
            "Scan %s completed: %d resources, %d findings in %.1fs",
            scan_id,
            result.resources_scanned,
            result.findings_count,
            result.duration_seconds,
        )
        return result

    async def _queue_findings(
        self, findings: list[FindingResult], tenant_id: str,
    ) -> int:
        """Send findings to Service Bus, respecting the tenant AI quota.

        Returns the number of findings *not* queued because the tenant has
        exhausted its monthly AI remediation cap. When billing/usage repos
        are not configured (legacy callers and most unit tests), all
        findings are queued -- preserves prior behaviour.
        """
        if not findings:
            return 0
        if (
            self._billing_repo is None
            or self._usage_repo is None
            or not tenant_id
        ):
            for finding in findings:
                await self._send_to_queue(finding)
            return 0

        quota = await check_ai_quota(
            tenant_id,
            billing_repo=self._billing_repo,
            usage_repo=self._usage_repo,
        )
        plan = get_plan(quota.tier)
        if plan.max_ai_remediations_per_month == UNLIMITED:
            for finding in findings:
                await self._send_to_queue(finding)
            return 0

        remaining = max(0, quota.cap - quota.current)
        if remaining == 0:
            return len(findings)

        ordered = sorted(findings, key=lambda f: f.priority_score, reverse=True)
        to_send = ordered[:remaining]
        for finding in to_send:
            await self._send_to_queue(finding)
        return max(0, len(findings) - len(to_send))

    async def _send_to_queue(self, finding: FindingResult) -> None:
        """Send a finding to the Service Bus queue."""
        if self._sender is None:
            logger.debug("No Service Bus sender configured -- skipping queue")
            return
        try:
            message_body = finding.model_dump_json()
            try:
                from azure.servicebus import ServiceBusMessage  # type: ignore[import-untyped]
                msg: object = ServiceBusMessage(message_body)
            except ImportError:
                msg = message_body
            await self._sender.send_messages(msg)
            logger.debug("Queued finding %s", finding.finding_id)
        except Exception as exc:
            logger.warning("Failed to queue finding %s: %s", finding.finding_id, exc)

    async def _save_scan_result(self, result: ScanResult) -> None:
        """Persist scan result to Cosmos DB via CosmosRepository."""
        if self._db is None:
            return
        doc = result.model_dump(mode="json")
        doc["id"] = result.scan_id
        doc["subscription_id"] = result.subscription_id
        doc["type"] = "scan_result"
        await self._db.save_scan_result(doc)
