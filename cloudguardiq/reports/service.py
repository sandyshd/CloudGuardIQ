"""Reports service: orchestrates generation, storage and metadata."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone

from cloudguardiq.compliance.scorecard import FRAMEWORKS, compute_scorecard
from cloudguardiq.core.enums import CloudProvider
from cloudguardiq.core.models import FindingResult
from cloudguardiq.reports.models import ReportRecord
from cloudguardiq.reports.pdf_generator import ComplianceReportGenerator
from cloudguardiq.reports.repository import ReportsRepository
from cloudguardiq.reports.storage import ReportStorage

logger = logging.getLogger(__name__)


class ReportsService:
    """Glue between the API layer and the generator / storage stack."""

    def __init__(
        self,
        *,
        generator: ComplianceReportGenerator,
        storage: ReportStorage,
        repository: ReportsRepository,
    ) -> None:
        self._generator = generator
        self._storage = storage
        self._repository = repository

    async def generate(
        self,
        *,
        subscription_id: str,
        framework: str,
        findings: Iterable[FindingResult],
        tenant_id: str = "",
        customer_name: str = "",
        generated_by: str = "",
        providers: set[CloudProvider] | None = None,
    ) -> tuple[ReportRecord, bytes]:
        """Generate a PDF, upload it, persist metadata, and return both."""
        framework_id = ComplianceReportGenerator._normalise_framework(framework)
        findings_list = list(findings)
        pdf_bytes = await self._generator.generate(
            subscription_id=subscription_id,
            framework=framework_id,
            findings=findings_list,
            customer_name=customer_name,
        )
        report_id = uuid.uuid4().hex
        blob_name = f"{subscription_id}/{framework_id}/{report_id}.pdf"
        download_url = await self._storage.upload(blob_name, pdf_bytes)

        scorecard = compute_scorecard(findings_list, providers=providers)
        row = next(
            (r for r in scorecard if r.framework_id == framework_id),
            None,
        )
        framework_label = next(
            (fw.label for fw in FRAMEWORKS if fw.id == framework_id),
            framework_id,
        )
        record = ReportRecord(
            report_id=report_id,
            tenant_id=tenant_id,
            subscription_id=subscription_id,
            framework_id=framework_id,
            framework_label=framework_label,
            score=row.score if row else 100,
            controls_total=row.controls_total if row else 0,
            controls_failed=row.controls_failed if row else 0,
            open_findings=row.open_findings if row else 0,
            size_bytes=len(pdf_bytes),
            blob_name=blob_name,
            download_url=download_url,
            generated_at=datetime.now(timezone.utc),
            generated_by=generated_by,
        )
        await self._repository.save(record)
        return record, pdf_bytes

    async def list_for_subscription(
        self,
        *,
        subscription_id: str,
        tenant_id: str = "",
        limit: int = 50,
    ) -> list[ReportRecord]:
        return await self._repository.list_for_subscription(
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            limit=limit,
        )

    async def get(self, report_id: str) -> ReportRecord | None:
        return await self._repository.get(report_id)

    async def download_bytes(self, record: ReportRecord) -> bytes | None:
        return await self._storage.download(record.blob_name)
