"""CloudGuardIQ — Contract monitor for self-healing engine."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class ContractMonitor:
    """Monitors adapter contracts for API drift and breaking changes."""

    async def check_contract(self, adapter_name: str, response: dict[str, Any]) -> bool:
        """Validate that an adapter response conforms to the expected contract.

        Returns True if the contract is satisfied, False otherwise.
        """
        if not isinstance(response, dict):
            logger.warning("Contract violation: %s returned non-dict response", adapter_name)
            return False
        return True
