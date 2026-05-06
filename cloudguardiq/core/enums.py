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
    """Cloud-agnostic data source tier for :class:`ResourceSnapshot`.

    The tier describes *how rich the signal is*, independent of any one
    cloud vendor. The legacy Azure-Defender-specific names (TIER2_FREE_CSPM
    / TIER3_PAID) remain valid aliases of the same wire values so existing
    rules, stored documents, and tests continue to work unchanged. New code
    should prefer the cloud-agnostic names.

    +-----+----------------------+----------------------+----------------------+
    | T   | Canonical name       | Azure equivalent     | AWS / GCP equivalent |
    +=====+======================+======================+======================+
    | 1   | TIER1_NATIVE         | Resource Graph only  | Config / SCC native  |
    | 2   | TIER2_ENRICHED       | Defender free CSPM   | Security Hub / SCC   |
    | 3   | TIER3_DEEP           | Defender paid plans  | GuardDuty / Inspector|
    +-----+----------------------+----------------------+----------------------+
    """

    TIER1_NATIVE = "TIER1_NATIVE"
    # Tier 2 -- vendor-detected free enrichment (Azure: Defender free CSPM,
    # AWS: Security Hub findings, GCP: SCC standard).
    TIER2_FREE_CSPM = "TIER2_FREE_CSPM"
    TIER2_ENRICHED = TIER2_FREE_CSPM  # cloud-agnostic alias (preferred)
    # Tier 3 -- paid deep telemetry (Azure: Defender for Servers/SQL/etc.,
    # AWS: GuardDuty + Inspector, GCP: SCC premium).
    TIER3_PAID = "TIER3_PAID"
    TIER3_DEEP = TIER3_PAID  # cloud-agnostic alias (preferred)


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


class FindingStatus(StrEnum):
    """Lifecycle state of a :class:`FindingResult`.

    A finding starts as ``OPEN`` when persisted by a scan. The user
    can move it to ``RESOLVED`` (issue handled outside CloudGuardIQ),
    ``SNOOZED`` (defer for N days), or ``APPLIED`` (auto-fix issued
    via the Self-Heal flow). Subsequent scans that re-detect the same
    underlying issue may flip the row back to ``OPEN``.
    """

    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    SNOOZED = "SNOOZED"
    APPLIED = "APPLIED"

