"""CloudGuardIQ -- AI remediation engine using Azure OpenAI GPT-4o."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from cloudguardiq.ai.prompt_templates import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE
from cloudguardiq.core.models import FindingResult, RemediationCard

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_REQUIRED_KEYS = {
    "narrative",
    "business_risk",
    "terraform_fix",
    "cli_fix",
    "confidence_qualifier",
    "estimated_savings_usd",
}


class AIEngineError(Exception):
    """Raised when AI remediation fails after all retries."""


class RemediationEngine:
    """Generate AI-powered remediation plans from FindingResult objects."""

    def __init__(
        self,
        client: Any,
        deployment: str = "gpt-4o",
        db: Any | None = None,
    ) -> None:
        """Initialise the engine.

        Args:
            client: An AsyncAzureOpenAI client instance.
            deployment: Azure OpenAI deployment name.
            db: Optional CosmosRepository for persisting cards.
        """
        self._client = client
        self._deployment = deployment
        self._db = db

    async def generate(self, finding: FindingResult) -> RemediationCard:
        """Generate an AI remediation plan for a single finding.

        Uses Azure OpenAI GPT-4o with structured JSON output mode.
        Retries up to 3 times on malformed JSON response.
        Saves result to Cosmos DB when a db is configured.
        """
        snapshot = finding.resource_snapshot
        finding_json = finding.model_dump_json(indent=2)

        user_prompt = USER_PROMPT_TEMPLATE.format(
            finding_json=finding_json,
            subscription_id=snapshot.subscription_id if snapshot else "",
            resource_group=snapshot.resource_group if snapshot else "",
            resource_name=snapshot.resource_name if snapshot else finding.resource_name,
            resource_type=snapshot.resource_type if snapshot else finding.resource_type,
            cost_monthly=f"{snapshot.cost_monthly:.2f}" if snapshot else "0.00",
            data_tier=snapshot.data_tier.value if snapshot else "TIER1_NATIVE",
            compliance_frameworks=", ".join(finding.compliance_frameworks) or "None",
        )

        last_error: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                data = await self._call_openai(user_prompt)
                card = RemediationCard(
                    finding_result=finding,
                    narrative=data.get("narrative", ""),
                    terraform_fix=data.get("terraform_fix", ""),
                    cli_fix=data.get("cli_fix", ""),
                    confidence_qualifier=data.get("confidence_qualifier", ""),
                    estimated_savings_usd=float(data.get("estimated_savings_usd", 0.0)),
                    model_version=self._deployment,
                    # Legacy fields populated for backward compat
                    summary=data.get("narrative", ""),
                    explanation=data.get("business_risk", ""),
                )
                if self._db is not None:
                    await self._db.save_remediation_card(card)
                return card
            except AIEngineError:
                raise
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "AI engine attempt %d/%d failed: %s",
                    attempt + 1,
                    _MAX_RETRIES,
                    exc,
                )

        raise AIEngineError(
            f"AI remediation failed after {_MAX_RETRIES} retries: {last_error}"
        )

    async def generate_batch(
        self,
        findings: list[FindingResult],
        max_concurrent: int = 5,
    ) -> list[RemediationCard]:
        """Generate remediation for a list of findings with concurrency control.

        Uses asyncio.Semaphore to avoid rate limiting.
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _limited(f: FindingResult) -> RemediationCard:
            async with semaphore:
                return await self.generate(f)

        return list(await asyncio.gather(*[_limited(f) for f in findings]))

    async def _call_openai(self, prompt: str) -> dict[str, Any]:
        """Call GPT-4o, parse response, validate against expected schema."""
        if self._client is None:
            raise AIEngineError("OpenAI client not configured")

        response = await self._client.chat.completions.create(
            model=self._deployment,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )
        content = response.choices[0].message.content
        if not isinstance(content, str):
            raise AIEngineError("Empty or non-string response from OpenAI")

        data = json.loads(content)
        if not isinstance(data, dict):
            raise ValueError("Response is not a JSON object")

        missing = _REQUIRED_KEYS - data.keys()
        if missing:
            raise ValueError(f"Response missing keys: {missing}")

        return data
