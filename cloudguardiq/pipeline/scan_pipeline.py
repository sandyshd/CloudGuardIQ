"""CloudGuardIQ -- Async scan pipeline."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

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
    ) -> None:
        """Initialise the scan pipeline.

        Args:
            adapter: Cloud adapter with async scan() method.
            policy_engine: PolicyEngine for evaluating snapshots.
            ai_engine: RemediationEngine (not used during scan -- AI is async).
            db: CosmosRepository for persisting scan results.
            service_bus_sender: Azure Service Bus sender for findings queue.
        """
        self._adapter = adapter
        self._policy_engine = policy_engine
        self._ai_engine = ai_engine
        self._db = db
        self._sender = service_bus_sender

    async def run(self, subscription_id: str) -> ScanResult:
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

        # Step 1: Scan resources
        try:
            snapshots = await self._adapter.scan()
        except Exception as exc:
            logger.error("Adapter scan failed for %s: %s", subscription_id, exc)
            raise

        # Step 2: Evaluate policies
        findings = self._policy_engine.evaluate(snapshots)

        # Defensive guard: ensure priority_score is computed for all findings
        for finding in findings:
            if finding.priority_score == 0.0:
                finding.compute_priority_score()

        # Step 3: Send findings to Service Bus queue
        for finding in findings:
            await self._send_to_queue(finding)

        # Step 4: Save findings to Cosmos DB
        if self._db is not None:
            for finding in findings:
                try:
                    await self._db.save_finding(finding)
                except Exception as exc:
                    logger.warning(
                        "Failed to save finding %s: %s", finding.finding_id, exc
                    )

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
                logger.warning("Failed to save scan result %s: %s", scan_id, exc)

        logger.info(
            "Scan %s completed: %d resources, %d findings in %.1fs",
            scan_id,
            result.resources_scanned,
            result.findings_count,
            result.duration_seconds,
        )
        return result

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
