"""CloudGuardIQ -- AI worker for processing findings from Service Bus queue."""

from __future__ import annotations

import json
import logging
from typing import Any

from cloudguardiq.ai.remediation_engine import AIEngineError, RemediationEngine
from cloudguardiq.core.models import FindingResult, RemediationCard

logger = logging.getLogger(__name__)


class AIWorker:
    """Processes findings from the Service Bus queue.

    Reads FindingResult messages, generates RemediationCards via AI engine,
    and persists results to Cosmos DB.
    """

    def __init__(
        self,
        ai_engine: RemediationEngine,
        db: Any,
    ) -> None:
        """Initialise the AI worker.

        Args:
            ai_engine: RemediationEngine for generating remediation cards.
            db: CosmosRepository for persisting results.
        """
        self._ai_engine = ai_engine
        self._db = db

    async def process_message(self, message_body: str) -> RemediationCard | None:
        """Process a single finding message from Service Bus.

        Args:
            message_body: JSON string of a FindingResult.

        Returns:
            RemediationCard if successful, None on failure.
        """
        try:
            data = json.loads(message_body)
            finding = FindingResult.model_validate(data)
        except (json.JSONDecodeError, Exception) as exc:
            logger.error("Failed to parse finding message: %s", exc)
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

        return card
