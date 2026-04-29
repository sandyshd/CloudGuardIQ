"""CloudGuardIQ -- AI worker for processing findings from Service Bus queue."""

from __future__ import annotations

import json
import logging
from typing import Any

from cloudguardiq.ai.remediation_engine import AIEngineError, RemediationEngine
from cloudguardiq.billing.quota import check_ai_quota, record_ai_remediation
from cloudguardiq.billing.repository import BillingRepository
from cloudguardiq.billing.usage import UsageRepository
from cloudguardiq.core.models import FindingResult, RemediationCard

logger = logging.getLogger(__name__)


class AIWorker:
    """Processes findings from the Service Bus queue.

    Reads FindingResult messages, generates RemediationCards via AI engine,
    and persists results to Cosmos DB.

    When *billing_repo* and *usage_repo* are supplied, the worker enforces
    the same per-tenant ``max_ai_remediations_per_month`` cap as the
    synchronous API path. If a tenant has exhausted its plan quota the
    message is logged and dropped (the work is silently shed) -- the queue
    is the wrong place to surface a billing error to the end-user.
    """

    def __init__(
        self,
        ai_engine: RemediationEngine,
        db: Any,
        *,
        billing_repo: BillingRepository | None = None,
        usage_repo: UsageRepository | None = None,
    ) -> None:
        """Initialise the AI worker.

        Args:
            ai_engine: RemediationEngine for generating remediation cards.
            db: CosmosRepository for persisting results.
            billing_repo: Billing repository (enables tier enforcement).
            usage_repo: Usage repository (required alongside *billing_repo*).
        """
        self._ai_engine = ai_engine
        self._db = db
        self._billing_repo = billing_repo
        self._usage_repo = usage_repo

    async def process_message(self, message_body: str) -> RemediationCard | None:
        """Process a single finding message from Service Bus.

        Args:
            message_body: JSON string of a FindingResult.

        Returns:
            RemediationCard if successful, None on failure or when the
            tenant's monthly AI quota has been exhausted.
        """
        try:
            data = json.loads(message_body)
            finding = FindingResult.model_validate(data)
        except (json.JSONDecodeError, Exception) as exc:
            logger.error("Failed to parse finding message: %s", exc)
            return None

        # --- Plan quota check (Phase 2.5) -------------------------------
        if self._billing_repo is not None and self._usage_repo is not None:
            tenant_id = finding.tenant_id or ""
            if tenant_id:
                quota = await check_ai_quota(
                    tenant_id,
                    billing_repo=self._billing_repo,
                    usage_repo=self._usage_repo,
                )
                if not quota.allowed:
                    logger.info(
                        "AI quota exhausted: tenant=%s tier=%s cap=%d -- dropping finding %s",
                        tenant_id, quota.tier.value, quota.cap, finding.finding_id,
                    )
                    return None

        try:
            card = await self._ai_engine.generate(finding)
        except AIEngineError as exc:
            logger.error(
                "AI generation failed for finding %s: %s",
                finding.finding_id,
                exc,
            )
            return None

        # Save remediation card to Cosmos DB
        if self._db is not None:
            try:
                await self._db.save_remediation_card(card)
                logger.info(
                    "Saved remediation card %s for finding %s",
                    card.card_id,
                    finding.finding_id,
                )
            except Exception as exc:
                logger.warning(
                    "Failed to save remediation card %s: %s",
                    card.card_id,
                    exc,
                )

        # Record usage on success only.
        if self._usage_repo is not None and finding.tenant_id:
            await record_ai_remediation(
                finding.tenant_id, usage_repo=self._usage_repo,
            )

        return card
