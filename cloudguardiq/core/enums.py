"""CloudGuardIQ -- Enums for data tier, cloud provider, severity, and finding category."""

from __future__ import annotations

import sys

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from enum import Enum

    class StrEnum(str, Enum):  # type: ignore[no-redef]
        """Backport of StrEnum for Python < 3.11."""


class DataTier(StrEnum):
    """Data source tier for ResourceSnapshot.

    TIER1_NATIVE  = Resource Graph only
    TIER2_FREE_CSPM = + Defender free
    TIER3_PAID    = + Defender paid plans
    """

    TIER1_NATIVE = "TIER1_NATIVE"
    TIER2_FREE_CSPM = "TIER2_FREE_CSPM"
    TIER3_PAID = "TIER3_PAID"


class CloudProvider(StrEnum):
    """Supported cloud providers."""

    AZURE = "AZURE"
    AWS = "AWS"
    GCP = "GCP"
    TERRAFORM = "TERRAFORM"


class Severity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingType(StrEnum):
    """Types of findings produced by the policy engine."""

    SECURITY = "SECURITY"
    FINOPS = "FINOPS"
    COMPLIANCE = "COMPLIANCE"


# ---------------------------------------------------------------------------
# Backward-compatible aliases (used by adapters/rules written before Phase 2)
# ---------------------------------------------------------------------------


class FindingCategory(StrEnum):
    """Categories of security / cost findings (legacy -- prefer FindingType)."""

    SECURITY = "SECURITY"
    COST = "COST"
    COMPLIANCE = "COMPLIANCE"


class RemediationStatus(StrEnum):
    """Status of a remediation card."""

    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    APPLIED = "APPLIED"
    FAILED = "FAILED"
    DISMISSED = "DISMISSED"


class SubscriptionTier(StrEnum):
    """Billing subscription tiers offered by CloudGuardIQ."""

    FREE = "FREE"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"
