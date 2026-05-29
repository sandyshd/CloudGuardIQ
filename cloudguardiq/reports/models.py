"""Pydantic models for compliance reports."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class ReportRecord(BaseModel):
    """Metadata for a generated compliance report PDF."""

    model_config = ConfigDict(frozen=False)

    report_id: str
    tenant_id: str = ""
    subscription_id: str
    framework_id: str
    framework_label: str = ""
    score: int = 0
    controls_total: int = 0
    controls_failed: int = 0
    open_findings: int = 0
    size_bytes: int = 0
    blob_name: str = ""
    download_url: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    generated_by: str = ""
