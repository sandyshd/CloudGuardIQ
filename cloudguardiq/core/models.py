"""CloudGuardIQ -- Core Pydantic v2 data models."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from cloudguardiq.core.enums import (
    CloudProvider,
    DataTier,
    FindingCategory,
    FindingStatus,
    FindingType,
    RemediationStatus,
    Severity,
)


def _looks_like_default_uuid(value: str) -> bool:
    """Return True when *value* looks like an auto-generated UUID4 string."""
    if not value or len(value) != 36:
        return False
    try:
        from uuid import UUID

        UUID(value, version=4)
        return True
    except (ValueError, AttributeError):
        return False


class ResourceSnapshot(BaseModel):
    """Canonical representation of a cloud resource at a point in time."""

    model_config = ConfigDict(frozen=False)

    id: str = ""
    tenant_id: str = ""
    provider: CloudProvider = CloudProvider.AZURE
    subscription_id: str
    resource_group: str
    resource_type: str
    resource_name: str
    region: str
    config: dict[str, Any] = Field(default_factory=dict)
    cost_monthly: float = 0.0
    tags: dict[str, str] = Field(default_factory=dict)
    data_tier: DataTier
    raw_hash: str = ""
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def build_id(
        cls,
        provider: CloudProvider,
        resource_type: str,
        subscription_id: str,
        resource_group: str,
        resource_name: str,
    ) -> str:
        """Generate a cloud-agnostic unique ID.

        Format: `<provider>/<short_type>/<sub>/<rg>/<name>` (all lower-case).
        """
        short_type = (
            resource_type.split("/")[-1].lower()
            if "/" in resource_type
            else resource_type.lower()
        )
        return "/".join(
            [
                provider.value.lower(),
                short_type,
                subscription_id.lower(),
                resource_group.lower(),
                resource_name.lower(),
            ]
        )

    def model_post_init(self, __context: Any) -> None:
        """Auto-populate `id` and `raw_hash` when not supplied."""
        if not self.id:
            self.id = self.build_id(
                self.provider,
                self.resource_type,
                self.subscription_id,
                self.resource_group,
                self.resource_name,
            )
        if not self.raw_hash:
            payload = json.dumps(self.config, sort_keys=True, default=str)
            self.raw_hash = hashlib.sha256(payload.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Backward-compatible property aliases for legacy code
    # ------------------------------------------------------------------

    @property
    def resource_id(self) -> str:
        """Alias kept for adapters/rules that still reference resource_id."""
        return self.id

    @property
    def location(self) -> str:
        """Alias kept for code that still references location."""
        return self.region

    @property
    def properties(self) -> dict[str, Any]:
        """Alias kept for rules that still reference properties."""
        return self.config

    @property
    def scanned_at(self) -> datetime:
        """Alias kept for code that still references scanned_at."""
        return self.captured_at


class FindingResult(BaseModel):
    """A security, FinOps, or compliance finding produced by the PolicyEngine."""

    model_config = ConfigDict(frozen=False)

    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str = ""
    resource_snapshot: ResourceSnapshot | None = None
    rule_id: str
    rule_name: str = ""
    severity: Severity
    finding_type: FindingType = FindingType.SECURITY
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    compliance_frameworks: list[str] = Field(default_factory=list)
    waste_monthly_usd: float = 0.0
    direct_waste_monthly_usd: float = 0.0
    estimated_impact_monthly_usd: float = 0.0
    finops_method: str = "NONE"
    finops_confidence: str = "LOW"
    priority_score: float = 0.0
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------------
    # Lifecycle (Phase 2.9 -- finding state transitions)
    # ------------------------------------------------------------------
    status: FindingStatus = FindingStatus.OPEN
    resolved_at: datetime | None = None
    resolved_by: str = ""
    snoozed_until: datetime | None = None
    applied_at: datetime | None = None

    # ------------------------------------------------------------------
    # Re-scan tracking -- populated by save_finding lifecycle merge
    # ------------------------------------------------------------------
    first_seen_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    last_seen_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    last_seen_scan_id: str = ""
    seen_count: int = 1

    # ------------------------------------------------------------------
    # Backward-compatible fields / aliases for legacy code
    # ------------------------------------------------------------------
    snapshot_id: Any | None = Field(default=None, exclude=True)
    title: str = Field(default="", exclude=True)
    category: FindingCategory | None = Field(default=None, exclude=True)
    resource_id: str = Field(default="", exclude=True)
    resource_type: str = Field(default="", exclude=True)
    resource_name: str = Field(default="", exclude=True)
    recommended_action: str = Field(default="", exclude=True)

    @property
    def id(self) -> str:  # noqa: A003
        """Alias for finding_id (legacy code uses .id)."""
        return self.finding_id

    @property
    def effective_monthly_impact_usd(self) -> float:
        """Return the best monthly cost impact signal for this finding."""
        return max(
            self.waste_monthly_usd,
            self.direct_waste_monthly_usd,
            self.estimated_impact_monthly_usd,
            0.0,
        )
    def model_post_init(self, __context: Any) -> None:
        """Populate rule_name, finding_type, and a deterministic finding_id.

        The default ``finding_id`` is a fresh UUID, which means consecutive
        scans of the same resource produce duplicate rows in Cosmos. To make
        re-scans idempotent (so existing OPEN/SNOOZED/RESOLVED state is
        preserved across scans), we replace the UUID with a stable hash of
        ``(tenant_id, subscription_id, rule_id, resource_id)`` whenever the
        caller did not explicitly supply one.

        Detecting "caller did not supply an id" is done structurally: the
        Pydantic default factory always produces a UUID4 string of length 36,
        so any value matching that shape is treated as auto-generated and
        replaced. Callers that pass a custom id are honoured verbatim.
        """
        if self.title and not self.rule_name:
            self.rule_name = self.title
        if self.category is not None and self.finding_type == FindingType.SECURITY:
            if self.category == FindingCategory.COST:
                self.finding_type = FindingType.FINOPS
            elif self.category == FindingCategory.COMPLIANCE:
                self.finding_type = FindingType.COMPLIANCE

        self.direct_waste_monthly_usd = max(
            self.direct_waste_monthly_usd,
            self.waste_monthly_usd,
            0.0,
        )
        if self.direct_waste_monthly_usd > 0.0:
            self.waste_monthly_usd = self.direct_waste_monthly_usd
            self.finops_method = "DIRECT"
            self.finops_confidence = "HIGH"
        elif self.estimated_impact_monthly_usd > 0.0 and self.finops_method == "NONE":
            self.finops_method = "ESTIMATED"
            if self.finops_confidence == "LOW":
                self.finops_confidence = "MEDIUM"

        if _looks_like_default_uuid(self.finding_id):
            stable = self._compute_stable_id()
            if stable:
                self.finding_id = stable

    def _compute_stable_id(self) -> str:
        """Return a deterministic id derived from rule + resource + tenant.

        Returns ``""`` (caller keeps its UUID) when there is not enough
        information to build a stable id -- e.g. legacy callers that build a
        FindingResult without a ResourceSnapshot. We never produce a partial
        hash because that would silently collide between unrelated rows.
        """
        snap = self.resource_snapshot
        resource_key = ""
        sub = ""
        if snap is not None:
            resource_key = snap.id or snap.resource_id or snap.resource_name
            sub = snap.subscription_id or ""
        elif self.snapshot_id:
            # Older rule call sites pass snapshot_id only (no full snapshot).
            # Hash the snapshot id alone so re-scans still produce a stable
            # finding_id; otherwise the auto-resolve sweep flips every prior
            # finding to RESOLVED on the next scan.
            resource_key = str(self.snapshot_id)
        if not (self.rule_id and resource_key):
            return ""
        material = "|".join([
            self.tenant_id or "",
            sub,
            self.rule_id,
            resource_key,
        ])
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def compute_priority_score(
        self,
        alpha: float = 0.5,
        beta: float = 0.3,
        gamma: float = 0.2,
    ) -> float:
        """Compute and set the priority score (0-100).

        Formula: `alpha * severity_score + beta * cost_score + gamma * compliance_score`
        """
        severity_map: dict[Severity, float] = {
            Severity.CRITICAL: 100.0,
            Severity.HIGH: 80.0,
            Severity.MEDIUM: 60.0,
            Severity.LOW: 40.0,
            Severity.INFORMATIONAL: 20.0,
        }
        severity_score = severity_map.get(self.severity, 0.0)
        cost_score = min(self.effective_monthly_impact_usd, 100.0)
        compliance_score = min(len(self.compliance_frameworks) * 25.0, 100.0)
        self.priority_score = round(
            alpha * severity_score + beta * cost_score + gamma * compliance_score,
            2,
        )
        return self.priority_score


class RemediationCard(BaseModel):
    """AI-generated remediation plan with Terraform fix code."""

    model_config = ConfigDict(frozen=False)

    card_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str = ""
    finding_result: FindingResult | None = None
    narrative: str = ""
    terraform_fix: str = ""
    cli_fix: str = ""
    confidence_qualifier: str = ""
    estimated_savings_usd: float = 0.0
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_version: str = ""

    # ------------------------------------------------------------------
    # Backward-compatible fields for legacy code
    # ------------------------------------------------------------------
    finding_id: Any | None = Field(default=None, exclude=True)
    summary: str = Field(default="", exclude=True)
    explanation: str = Field(default="", exclude=True)
    risk_if_ignored: str = Field(default="", exclude=True)
    terraform_code: str = Field(default="", exclude=True)
    manual_steps: list[str] = Field(default_factory=list, exclude=True)
    status: RemediationStatus = Field(default=RemediationStatus.PENDING, exclude=True)

    @property
    def id(self) -> str:  # noqa: A003
        """Alias for card_id (legacy code uses .id)."""
        return self.card_id

    def model_post_init(self, __context: Any) -> None:
        """Populate new fields from legacy fields when provided."""
        if self.summary and not self.narrative:
            self.narrative = self.summary
        if self.terraform_code and not self.terraform_fix:
            self.terraform_fix = self.terraform_code


class ScanRequest(BaseModel):
    """API request to trigger a subscription scan."""

    subscription_id: str
    include_cost: bool = True


class ScanResponse(BaseModel):
    """API response after scan completes."""

    subscription_id: str
    snapshots_count: int
    findings_count: int
    findings: list[FindingResult] = Field(default_factory=list)



