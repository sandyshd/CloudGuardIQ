"""CloudGuardIQ -- Async scan pipeline."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cloudguardiq.adapters.pricing.live_prices import refresh_prices
from cloudguardiq.billing.plans import (
    UNLIMITED,
    PlanLimits,
    get_plan,
    is_unlimited,
)
from cloudguardiq.billing.quota import check_ai_quota
from cloudguardiq.billing.repository import BillingRepository
from cloudguardiq.billing.usage import UsageRepository
from cloudguardiq.core.enums import Severity, SubscriptionTier
from cloudguardiq.core.models import FindingResult
from cloudguardiq.pipeline.resource_cap import cap_snapshots
from cloudguardiq.policy.engine import dedupe_findings_by_id

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
        auto_generate_ai: bool = False,
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
        self._auto_generate_ai = auto_generate_ai

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

        # Step 1b: bound the inventory to the tenant's plan tier (defense
        # in depth alongside the API middleware). Highest-value resources
        # -- rule-covered and costly -- are retained when truncation is
        # required so small tiers still scan what matters most.
        plan = await self._resolve_plan(tenant_id)
        cap = plan.max_resources_per_scan
        if not is_unlimited(cap) and len(snapshots) > cap:
            snapshots, dropped = cap_snapshots(
                snapshots,
                cap,
                covered_types=self._covered_resource_types(),
                tenant_id=tenant_id,
                tier=plan.tier.value,
            )
            logger.warning(
                "Scan %s truncated inventory for tenant=%s tier=%s: "
                "kept %d of %d (cap=%d, dropped=%d)",
                scan_id, tenant_id or "<unknown>", plan.tier.value,
                len(snapshots), len(snapshots) + dropped, cap, dropped,
            )

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

        # Step 2c: Merge Defender for Cloud findings (Tier 2/3). These cover
        # resource types with no native rule. When a Defender assessment
        # overlaps a native rule that already fired for the same resource we
        # drop the Defender duplicate and keep the richer native finding.
        defender_findings = getattr(self._adapter, "defender_findings", None)
        if defender_findings:
            kept = self._dedupe_defender_against_native(
                findings, defender_findings,
            )
            findings.extend(kept)
            logger.info(
                "Merged %d Defender finding(s) into scan %s "
                "(%d dropped as native duplicates)",
                len(kept),
                scan_id,
                len(defender_findings) - len(kept),
            )

        # Collapse finding_id collisions from the policy merge so the
        # persisted (deduped) count matches the reported findings_count.
        findings = dedupe_findings_by_id(findings)
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
        # AI auto-generation is opt-in. By default we do NOT queue findings
        # for GPT remediation on every scan -- that spends tokens on findings
        # nobody opens. Cards are generated lazily when a user clicks
        # 'Get AI remediation' in the UI. Set ai_autogenerate_on_scan=True
        # (wired via auto_generate_ai) to restore eager pre-generation.
        if self._auto_generate_ai:
            deferred_count = await self._queue_findings(findings, tenant_id)
            if deferred_count:
                logger.info(
                    "Deferred %d finding(s) past tenant=%s AI quota; "
                    "raw findings still saved -- upgrade to unlock more",
                    deferred_count, tenant_id or "<unknown>",
                )
        else:
            logger.info(
                "AI auto-generation disabled -- not queuing %d finding(s) "
                "for GPT; remediation cards are generated on demand.",
                len(findings),
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

    @staticmethod
    def _dedupe_defender_against_native(
        native_findings: list[FindingResult],
        defender_findings: list[FindingResult],
    ) -> list[FindingResult]:
        """Drop Defender findings that duplicate a fired native rule.

        A Defender finding is dropped only when its evidence declares it
        overlaps a specific native rule (``native_rule_overlap``) AND that
        rule actually fired for the same resource (``resource_key``).
        Defender findings without a declared overlap -- the common case for
        resource types lacking native rules -- are always kept.

        Args:
            native_findings: Findings already produced by the rule engine
                and policy merge (the preferred source on overlap).
            defender_findings: Candidate Defender findings to merge.

        Returns:
            The subset of ``defender_findings`` to keep.
        """
        native_keys: set[tuple[str, str]] = set()
        for finding in native_findings:
            snap = finding.resource_snapshot
            if snap is None:
                continue
            rkey = f"{snap.resource_group.lower()}/{snap.resource_name.lower()}"
            native_keys.add((rkey, finding.rule_id))
        kept: list[FindingResult] = []
        for finding in defender_findings:
            overlap = str(finding.evidence.get("native_rule_overlap") or "")
            resource_key = str(finding.evidence.get("resource_key") or "")
            if overlap and (resource_key, overlap) in native_keys:
                continue
            kept.append(finding)
        return kept

    async def _resolve_plan(self, tenant_id: str) -> PlanLimits:
        """Resolve the tenant's plan; defaults to FREE when unknown.

        Reuses the billing-repo tier lookup that AI quota enforcement
        relies on, so the resource cap and the AI cap share one tier
        source. Best-effort: any billing failure falls back to FREE so a
        metering hiccup never blocks or over-caps a scan.
        """
        tier = SubscriptionTier.FREE
        if self._billing_repo is not None and tenant_id:
            try:
                record = await self._billing_repo.get(tenant_id)
                if record is not None:
                    tier = record.tier
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Tier lookup failed for tenant %s: %s -- "
                    "defaulting to FREE",
                    tenant_id, exc,
                )
        return get_plan(tier)

    def _covered_resource_types(self) -> frozenset[str]:
        """Return rule-covered resource types from the policy engine.

        Defensive: engines that predate ``covered_resource_types`` (or
        test doubles) yield an empty set so capping falls back to pure
        cost ordering rather than failing.
        """
        getter = getattr(self._policy_engine, "covered_resource_types", None)
        if not callable(getter):
            return frozenset()
        try:
            return frozenset(str(t).lower() for t in getter())
        except Exception:  # noqa: BLE001
            return frozenset()

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
