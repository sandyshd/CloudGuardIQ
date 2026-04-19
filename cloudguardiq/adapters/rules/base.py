"""CloudGuardIQ — Abstract base class for NativeScanner policy rules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class PolicyRule(ABC):
    """Abstract base class for all NativeScanner rules.

    Subclasses must set class-level attributes and implement ``evaluate``.
    """

    rule_id: str
    rule_name: str
    severity: Severity
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = []

    @abstractmethod
    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Evaluate *snapshot* against this rule.

        Args:
            snapshot: The resource snapshot to check.

        Returns:
            A ``FindingResult`` when the resource violates the rule, or
            ``None`` when the resource passes.
        """
