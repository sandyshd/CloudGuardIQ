"""CloudGuardIQ — Drift detector for self-healing engine."""

from __future__ import annotations

import logging

from cloudguardiq.core.models import ResourceSnapshot

logger = logging.getLogger(__name__)


class DriftDetector:
    """Detects configuration drift between expected and actual resource state."""

    async def detect_drift(
        self, expected: ResourceSnapshot, actual: ResourceSnapshot
    ) -> dict[str, tuple[object, object]]:
        """Compare two snapshots and return differing properties.

        Returns a dict of {property_name: (expected_value, actual_value)}.
        """
        diffs: dict[str, tuple[object, object]] = {}
        for key in expected.properties:
            exp_val = expected.properties.get(key)
            act_val = actual.properties.get(key)
            if exp_val != act_val:
                diffs[key] = (exp_val, act_val)
        return diffs
