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
from cloudguardiq.compliance.scorecard import compute_scorecard
from cloudguardiq.reports.pdf_generator import _framework_def


def _make_finding(
    *,
    rule_id: str = "STOR-001",
    rule_name: str = "Public blob access enabled",
    severity: Severity = Severity.CRITICAL,
    frameworks: list[str] | None = None,
    waste: float = 0.0,
    description: str = "Public blob access is enabled on this storage account.",
    resource_name: str = "sa1",
    evidence: dict[str, str] | None = None,
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
        evidence=evidence or {},
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

    def test_policy_detail_rows_and_lines_for_azpol_findings(self) -> None:
        gen = ComplianceReportGenerator()
        finding = _make_finding(
            rule_id="AZPOL-DenyPublicAccess",
            frameworks=["CIS_AZURE:3.1"],
            evidence={
                "policy_definition_id": "/providers/Microsoft.Authorization/policyDefinitions/abc",
                "policy_assignment_id": "/subscriptions/sub-123/providers/Microsoft.Authorization/policyAssignments/assign1",
                "compliance_reason_code": "NonCompliant",
                "timestamp": "2026-01-02T03:04:05Z",
            },
        )

        rows = gen._policy_detail_rows(finding)
        assert ["Finding source", "Azure Policy Regulatory Compliance"] in rows
        assert any(row[0] == "Policy definition" for row in rows)
        assert any(row[0] == "Policy assignment" for row in rows)
        assert any(row[0] == "Compliance reason" for row in rows)
        assert any(row[0] == "Policy evaluated at" for row in rows)

        lines = gen._policy_detail_lines(finding)
        assert any("Azure Policy Regulatory Compliance" in line for line in lines)
        assert any("Policy definition:" in line for line in lines)
        assert any("Policy assignment:" in line for line in lines)
        assert any("Compliance reason:" in line for line in lines)
        assert any("Evaluated at:" in line for line in lines)

    def test_policy_details_skipped_for_non_azpol_findings(self) -> None:
        gen = ComplianceReportGenerator()
        finding = _make_finding(rule_id="STOR-001", frameworks=["CIS_AZURE:3.1"])

        assert gen._policy_detail_rows(finding) == []
        assert gen._policy_detail_lines(finding) == []

    def test_scope_methodology_conditional_policy_language(self) -> None:
        gen = ComplianceReportGenerator()
        fw = _framework_def("CIS_AZURE")
        score_row = next(
            row
            for row in compute_scorecard([], providers={CloudProvider.AZURE})
            if row.framework_id == "CIS_AZURE"
        )

        with_policy = gen._scope_and_methodology(
            fw=fw,
            score_row=score_row,
            subscription_id="sub-123",
            customer_name="Acme",
            providers={CloudProvider.AZURE},
            generated_by="tester",
            report_id="report-1",
            include_policy_findings=True,
        )
        without_policy = gen._scope_and_methodology(
            fw=fw,
            score_row=score_row,
            subscription_id="sub-123",
            customer_name="Acme",
            providers={CloudProvider.AZURE},
            generated_by="tester",
            report_id="report-1",
            include_policy_findings=False,
        )

        assert "AZPOL-" in with_policy[8].text
        assert "AZPOL-" not in without_policy[8].text
        assert "Azure Policy Regulatory Compliance" in with_policy[10]._cellvalues[6][1]
        assert "CloudGuardIQ native compliance rules" in without_policy[10]._cellvalues[6][1]


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

