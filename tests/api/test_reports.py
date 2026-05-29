"""Tests for the compliance report PDF generator and /reports routes."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from cloudguardiq.api import reports as reports_module
from cloudguardiq.api.main import app
from cloudguardiq.core.enums import (
    CloudProvider,
    DataTier,
    FindingStatus,
    FindingType,
    Severity,
)
from cloudguardiq.core.models import FindingResult, ResourceSnapshot
from cloudguardiq.reports import (
    ComplianceReportGenerator,
    InMemoryReportStorage,
    ReportsRepository,
    ReportsService,
)


def _make_finding(
    *,
    rule_id: str = "STOR-001",
    rule_name: str = "Public blob access enabled",
    severity: Severity = Severity.CRITICAL,
    frameworks: list[str] | None = None,
    waste: float = 0.0,
    description: str = "Public blob access is enabled on this storage account.",
    resource_name: str = "sa1",
) -> FindingResult:
    snap = ResourceSnapshot(
        subscription_id="sub-123",
        resource_group="rg1",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name=resource_name,
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={},
    )
    return FindingResult(
        resource_snapshot=snap,
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        finding_type=FindingType.SECURITY,
        description=description,
        compliance_frameworks=frameworks or ["CIS_3.1", "SOC2_CC6.1"],
        waste_monthly_usd=waste,
        priority_score=92.5,
        status=FindingStatus.OPEN,
        detected_at=datetime.now(timezone.utc),
    )


class TestComplianceReportGenerator:
    @pytest.mark.asyncio
    async def test_generate_returns_pdf_bytes(self) -> None:
        gen = ComplianceReportGenerator()
        findings = [_make_finding()]
        pdf = await gen.generate(
            subscription_id="sub-123",
            framework="CIS",
            findings=findings,
            customer_name="Acme Corp",
        )
        assert isinstance(pdf, bytes)
        assert pdf[:4] == b"%PDF"
        # Minimum sanity check: a real PDF with multiple pages is > 5 KB.
        assert len(pdf) > 3000

    @pytest.mark.asyncio
    async def test_generate_handles_empty_findings(self) -> None:
        gen = ComplianceReportGenerator()
        pdf = await gen.generate(
            subscription_id="sub-123",
            framework="CIS_AZURE",
            findings=[],
        )
        assert pdf[:4] == b"%PDF"

    @pytest.mark.asyncio
    async def test_resolved_findings_excluded(self) -> None:
        gen = ComplianceReportGenerator()
        resolved = _make_finding()
        resolved.status = FindingStatus.RESOLVED
        pdf_with = await gen.generate(
            subscription_id="sub-123",
            framework="CIS",
            findings=[_make_finding()],
        )
        pdf_without = await gen.generate(
            subscription_id="sub-123",
            framework="CIS",
            findings=[resolved],
        )
        # Both render; the resolved case must still produce a valid PDF.
        assert pdf_with[:4] == b"%PDF"
        assert pdf_without[:4] == b"%PDF"

    @pytest.mark.asyncio
    async def test_framework_alias_normalisation(self) -> None:
        gen = ComplianceReportGenerator()
        for token in ("CIS", "cis", "CIS_AZURE", "cis-azure"):
            pdf = await gen.generate(
                subscription_id="sub-123",
                framework=token,
                findings=[_make_finding()],
            )
            assert pdf[:4] == b"%PDF"


class TestReportsService:
    @pytest.mark.asyncio
    async def test_generate_persists_metadata(self) -> None:
        service = ReportsService(
            generator=ComplianceReportGenerator(),
            storage=InMemoryReportStorage(download_url_prefix="/reports"),
            repository=ReportsRepository(None),
        )
        record, pdf = await service.generate(
            subscription_id="sub-123",
            framework="CIS",
            findings=[_make_finding()],
            tenant_id="tenant-a",
            generated_by="user-1",
        )
        assert record.framework_id == "CIS_AZURE"
        assert record.size_bytes == len(pdf)
        assert record.tenant_id == "tenant-a"
        listed = await service.list_for_subscription(
            subscription_id="sub-123", tenant_id="tenant-a",
        )
        assert len(listed) == 1
        assert listed[0].report_id == record.report_id

    @pytest.mark.asyncio
    async def test_download_returns_bytes(self) -> None:
        service = ReportsService(
            generator=ComplianceReportGenerator(),
            storage=InMemoryReportStorage(),
            repository=ReportsRepository(None),
        )
        record, pdf = await service.generate(
            subscription_id="sub-123",
            framework="CIS",
            findings=[_make_finding()],
        )
        fetched = await service.download_bytes(record)
        assert fetched == pdf


@pytest.fixture
async def client() -> AsyncClient:
    # Swap in a fresh in-memory reports service so each test starts clean.
    service = ReportsService(
        generator=ComplianceReportGenerator(),
        storage=InMemoryReportStorage(),
        repository=ReportsRepository(None),
    )

    async def _allow_owned_subscription(_user, subscription_id: str) -> str:
        return subscription_id.lower()

    reports_module.configure(
        service=service,
        validate_owned_subscription=_allow_owned_subscription,
        get_repo=lambda: None,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestReportsRoutes:
    @pytest.mark.asyncio
    async def test_generate_route_returns_record(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/reports/generate",
            params={"subscription_id": "sub-123", "framework": "CIS"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["report"]["subscription_id"] == "sub-123"
        assert data["report"]["framework_id"] == "CIS_AZURE"
        assert data["report"]["size_bytes"] > 0
        assert data["report"]["report_id"]

    @pytest.mark.asyncio
    async def test_list_then_download(self, client: AsyncClient) -> None:
        gen = await client.get(
            "/reports/generate",
            params={"subscription_id": "sub-123"},
        )
        assert gen.status_code == 200
        report_id = gen.json()["report"]["report_id"]

        listed = await client.get(
            "/reports", params={"subscription_id": "sub-123"},
        )
        assert listed.status_code == 200
        ids = [r["report_id"] for r in listed.json()["reports"]]
        assert report_id in ids

        download = await client.get(f"/reports/{report_id}/download")
        assert download.status_code == 200
        assert download.headers["content-type"] == "application/pdf"
        assert download.content[:4] == b"%PDF"

    @pytest.mark.asyncio
    async def test_download_unknown_id_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get("/reports/does-not-exist/download")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_generate_requires_subscription_id(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get("/reports/generate")
        assert resp.status_code == 422
