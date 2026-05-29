"""CloudGuardIQ -- compliance report FastAPI routes."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel

from cloudguardiq.api.auth import TokenPayload, get_tenant_id, verify_token
from cloudguardiq.core.config import get_settings
from cloudguardiq.core.observability import bind_context
from cloudguardiq.reports.models import ReportRecord
from cloudguardiq.reports.service import ReportsService

logger = logging.getLogger(__name__)

_service: ReportsService | None = None
_validate_owned_subscription: Any = None
_get_repo: Any = None


def configure(
    *,
    service: ReportsService,
    validate_owned_subscription: Any,
    get_repo: Any,
) -> None:
    """Wire the reports service and helpers from the main app."""
    global _service, _validate_owned_subscription, _get_repo  # noqa: PLW0603
    _service = service
    _validate_owned_subscription = validate_owned_subscription
    _get_repo = get_repo


def _require_service() -> ReportsService:
    if _service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Reports service not configured",
        )
    return _service


class GenerateResponse(BaseModel):
    report: ReportRecord


class ReportListResponse(BaseModel):
    reports: list[ReportRecord]


router = APIRouter(prefix="/reports", tags=["reports"])

_auth = Depends(verify_token)


@router.get("/generate", response_model=GenerateResponse)
async def generate_report(
    subscription_id: str = Query(..., min_length=1),
    framework: str = Query("CIS"),
    user: TokenPayload = _auth,
) -> GenerateResponse:
    """Generate a compliance report PDF for *subscription_id* and *framework*."""
    if _validate_owned_subscription is None or _get_repo is None:
        raise HTTPException(status_code=503, detail="Reports service not configured")
    service = _require_service()
    sub_id = await _validate_owned_subscription(user, subscription_id)
    bind_context(subscription_id=sub_id, provider="azure")

    settings = get_settings()
    tenant_id = "" if settings.auth_disabled else get_tenant_id(user)
    generated_by = user.oid or user.sub or ""

    repo = _get_repo()
    findings: list = []
    if repo is not None:
        try:
            findings = await repo.get_findings(
                sub_id,
                tenant_id=tenant_id,
                limit=5000,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load findings for report: %s", exc)
            findings = []

    record, _ = await service.generate(
        subscription_id=sub_id,
        framework=framework,
        findings=findings,
        tenant_id=tenant_id,
        generated_by=generated_by,
    )
    return GenerateResponse(report=record)


@router.get("", response_model=ReportListResponse)
async def list_reports(
    subscription_id: str = Query(..., min_length=1),
    limit: int = Query(50, ge=1, le=200),
    user: TokenPayload = _auth,
) -> ReportListResponse:
    """List previously generated reports for *subscription_id*."""
    if _validate_owned_subscription is None:
        raise HTTPException(status_code=503, detail="Reports service not configured")
    service = _require_service()
    sub_id = await _validate_owned_subscription(user, subscription_id)
    settings = get_settings()
    tenant_id = "" if settings.auth_disabled else get_tenant_id(user)
    records = await service.list_for_subscription(
        subscription_id=sub_id,
        tenant_id=tenant_id,
        limit=limit,
    )
    return ReportListResponse(reports=records)


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    user: TokenPayload = _auth,
) -> Response:
    """Stream the report PDF inline. Enforces tenant ownership."""
    if _validate_owned_subscription is None:
        raise HTTPException(status_code=503, detail="Reports service not configured")
    service = _require_service()
    record = await service.get(report_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Report not found")
    # Defence in depth: reuse the subscription-ownership check so a tenant
    # cannot download a report belonging to another tenant by guessing a
    # report_id.
    await _validate_owned_subscription(user, record.subscription_id)
    settings = get_settings()
    if not settings.auth_disabled:
        tenant_id = get_tenant_id(user)
        if record.tenant_id and record.tenant_id != tenant_id:
            raise HTTPException(status_code=404, detail="Report not found")

    pdf_bytes = await service.download_bytes(record)
    if pdf_bytes is None:
        raise HTTPException(status_code=404, detail="Report content missing")
    filename = f"{record.framework_id.lower()}-{record.report_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
    )
