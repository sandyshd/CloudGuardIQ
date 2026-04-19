"""CloudGuardIQ — AI remediation engine using Azure OpenAI GPT-4o."""

from __future__ import annotations

import json
import logging
import os
from typing import Any, cast

from cloudguardiq.ai.prompt_templates import (
    REMEDIATION_SYSTEM_PROMPT,
    REMEDIATION_USER_TEMPLATE,
)
from cloudguardiq.core.models import FindingResult, RemediationCard

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3


class AIEngineError(Exception):
    """Raised when AI remediation fails after all retries."""


class RemediationEngine:
    """Generate AI-powered remediation plans from FindingResult objects."""

    def __init__(self, client: Any = None) -> None:
        self._client = client
        self._model = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")

    async def generate(self, finding: FindingResult) -> RemediationCard:
        """Generate a remediation card for a single finding.

        Retries up to 3 times with exponential backoff, then raises AIEngineError.
        """
        finding_json = finding.model_dump_json(indent=2)
        category = finding.category.value if finding.category is not None else "unknown"
        user_prompt = REMEDIATION_USER_TEMPLATE.format(
            finding_json=finding_json,
            resource_type=finding.resource_type,
            resource_name=finding.resource_name,
            severity=finding.severity.value,
            category=category,
        )

        last_error: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                response = await self._call_openai(user_prompt)
                return self._parse_response(finding, response)
            except AIEngineError:
                raise
            except Exception as exc:
                last_error = exc
                logger.warning(
                    "AI engine attempt %d/%d failed: %s", attempt + 1, _MAX_RETRIES, exc
                )

        raise AIEngineError(
            f"AI remediation failed after {_MAX_RETRIES} retries: {last_error}"
        )

    async def _call_openai(self, user_prompt: str) -> dict[str, Any]:
        """Call Azure OpenAI GPT-4o."""
        if self._client is None:
            raise AIEngineError("OpenAI client not configured")

        response = await self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": REMEDIATION_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )
        content = response.choices[0].message.content
        if not isinstance(content, str):
            raise AIEngineError("Empty or non-string response content from OpenAI")
        return cast(dict[str, Any], json.loads(content))

    def _parse_response(
        self, finding: FindingResult, response: dict[str, Any]
    ) -> RemediationCard:
        """Parse GPT-4o response into a RemediationCard."""
        return RemediationCard(
            finding_id=finding.id,
            summary=response.get("summary", ""),
            explanation=response.get("explanation", ""),
            risk_if_ignored=response.get("risk_if_ignored", ""),
            terraform_code=response.get("terraform_code", ""),
            manual_steps=response.get("manual_steps", []),
        )
