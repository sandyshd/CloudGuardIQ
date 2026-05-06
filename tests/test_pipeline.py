"""Tests for scan pipeline, AI worker, and API endpoints."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from cloudguardiq.api import subscriptions as subs_module
from cloudguardiq.core.enums import DataTier, Severity
from cloudguardiq.core.models import FindingResult, RemediationCard, ResourceSnapshot
from cloudguardiq.pipeline.ai_worker import AIWorker
from cloudguardiq.pipeline.scan_pipeline import ScanPipeline, ScanResult
from cloudguardiq.subscriptions.repository import SubscriptionRecord

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def mock_snapshots() -> list[ResourceSnapshot]:
    """Create test snapshots."""
    return [
        ResourceSnapshot(
            subscription_id="sub-test",
            resource_group="rg1",
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="sa1",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
            config={"supportsHttpsTrafficOnly": False},
        ),
        ResourceSnapshot(
            subscription_id="sub-test",
            resource_group="rg1",
            resource_type="Microsoft.Compute/virtualMachines",
            resource_name="vm1",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
            config={"avgCpuPercent": 2.0},
            cost_monthly=150.0,
        ),
    ]


@pytest.fixture
def mock_findings() -> list[FindingResult]:
    """Create test findings."""
    return [
        FindingResult(
            rule_id="STORAGE-001",
            rule_name="Storage HTTPS Only",
            severity=Severity.HIGH,
            description="HTTPS not enforced",
            resource_snapshot=ResourceSnapshot(
                subscription_id="sub-test",
                resource_group="rg1",
                resource_type="Microsoft.Storage/storageAccounts",
                resource_name="sa1",
                region="eastus",
                data_tier=DataTier.TIER1_NATIVE,
            ),
        ),
        FindingResult(
            rule_id="FINOPS-002",
            rule_name="Underutilized VM",
            severity=Severity.MEDIUM,
            description="VM underutilized",
            waste_monthly_usd=120.0,
            resource_snapshot=ResourceSnapshot(
                subscription_id="sub-test",
                resource_group="rg1",
                resource_type="Microsoft.Compute/virtualMachines",
                resource_name="vm1",
                region="eastus",
                data_tier=DataTier.TIER1_NATIVE,
            ),
        ),
        FindingResult(
            rule_id="NET-001",
            rule_name="Open SSH",
            severity=Severity.CRITICAL,
            description="SSH open to internet",
            resource_snapshot=ResourceSnapshot(
                subscription_id="sub-test",
                resource_group="rg1",
                resource_type="Microsoft.Network/networkSecurityGroups",
                resource_name="nsg1",
                region="eastus",
                data_tier=DataTier.TIER1_NATIVE,
            ),
        ),
    ]


@pytest.fixture
def mock_adapter(mock_snapshots: list[ResourceSnapshot]) -> AsyncMock:
    """Mock adapter with scan() method."""
    adapter = AsyncMock()
    adapter.scan.return_value = mock_snapshots
    return adapter


@pytest.fixture
def mock_policy_engine(mock_findings: list[FindingResult]) -> MagicMock:
    """Mock policy engine with evaluate() method."""
    engine = MagicMock()
    engine.evaluate.return_value = mock_findings
    return engine


@pytest.fixture
def mock_ai_engine() -> AsyncMock:
    """Mock AI engine with generate() method."""
    engine = AsyncMock()
    engine.generate.return_value = RemediationCard(
        narrative="Fix the issue",
        terraform_fix='resource "example" {}',
        confidence_qualifier="high",
        model_version="gpt-5.1",
    )
    return engine


@pytest.fixture
def mock_db() -> MagicMock:
    """Mock Cosmos DB repository."""
    db = MagicMock()
    db.save_finding = AsyncMock(return_value="finding-id")
    db.save_remediation_card = AsyncMock(return_value="card-id")
    db.save_scan_result = AsyncMock(return_value=None)
    db.get_scan_result = AsyncMock(return_value=None)
    return db


@pytest.fixture
def mock_sender() -> AsyncMock:
    """Mock Service Bus sender."""
    return AsyncMock()


# ------------------------------------------------------------------
# ScanPipeline tests
# ------------------------------------------------------------------


class TestScanPipeline:
    """Tests for the ScanPipeline class."""

    @pytest.mark.asyncio
    async def test_pipeline_run_e2e(
        self,
        mock_adapter: AsyncMock,
        mock_policy_engine: MagicMock,
        mock_ai_engine: AsyncMock,
        mock_db: MagicMock,
        mock_sender: AsyncMock,
    ) -> None:
        """Test full pipeline run with mocked dependencies."""
        pipeline = ScanPipeline(
            adapter=mock_adapter,
            policy_engine=mock_policy_engine,
            ai_engine=mock_ai_engine,
            db=mock_db,
            service_bus_sender=mock_sender,
        )

        result = await pipeline.run("sub-test")

        assert isinstance(result, ScanResult)
        assert result.subscription_id == "sub-test"
        assert result.resources_scanned == 2
        assert result.findings_count == 3
        assert result.duration_seconds >= 0
        assert result.scan_id

        # Verify adapter was called
        mock_adapter.scan.assert_awaited_once()

        # Verify policy engine was called with snapshots
        mock_policy_engine.evaluate.assert_called_once()

        # Verify findings were sent to queue
        assert mock_sender.send_messages.await_count == 3

        # Verify findings were saved to DB
        assert mock_db.save_finding.await_count == 3

    @pytest.mark.asyncio
    async def test_scan_result_counts_correct(
        self,
        mock_adapter: AsyncMock,
        mock_policy_engine: MagicMock,
        mock_ai_engine: AsyncMock,
        mock_db: MagicMock,
    ) -> None:
        """Test that ScanResult severity counts are accurate."""
        pipeline = ScanPipeline(
            adapter=mock_adapter,
            policy_engine=mock_policy_engine,
            ai_engine=mock_ai_engine,
            db=mock_db,
        )

        result = await pipeline.run("sub-test")

        # 1 CRITICAL, 1 HIGH, 1 MEDIUM from mock_findings
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.total_waste_usd == 120.0

    @pytest.mark.asyncio
    async def test_pipeline_no_service_bus(
        self,
        mock_adapter: AsyncMock,
        mock_policy_engine: MagicMock,
        mock_ai_engine: AsyncMock,
        mock_db: MagicMock,
    ) -> None:
        """Test pipeline runs without Service Bus sender."""
        pipeline = ScanPipeline(
            adapter=mock_adapter,
            policy_engine=mock_policy_engine,
            ai_engine=mock_ai_engine,
            db=mock_db,
            service_bus_sender=None,
        )

        result = await pipeline.run("sub-test")
        assert result.findings_count == 3

    @pytest.mark.asyncio
    async def test_pipeline_no_db(
        self,
        mock_adapter: AsyncMock,
        mock_policy_engine: MagicMock,
        mock_ai_engine: AsyncMock,
    ) -> None:
        """Test pipeline runs without Cosmos DB."""
        pipeline = ScanPipeline(
            adapter=mock_adapter,
            policy_engine=mock_policy_engine,
            ai_engine=mock_ai_engine,
            db=None,
        )

        result = await pipeline.run("sub-test")
        assert result.findings_count == 3


# ------------------------------------------------------------------
# AIWorker tests
# ------------------------------------------------------------------


class TestAIWorker:
    """Tests for the AIWorker class."""

    @pytest.mark.asyncio
    async def test_ai_worker_saves_remediation_card(
        self,
        mock_ai_engine: AsyncMock,
        mock_db: MagicMock,
    ) -> None:
        """Test AI worker generates and saves a RemediationCard."""
        worker = AIWorker(ai_engine=mock_ai_engine, db=mock_db)

        finding = FindingResult(
            rule_id="STORAGE-001",
            rule_name="Storage HTTPS Only",
            severity=Severity.HIGH,
            description="HTTPS not enforced",
            resource_snapshot=ResourceSnapshot(
                subscription_id="sub-test",
                resource_group="rg1",
                resource_type="Microsoft.Storage/storageAccounts",
                resource_name="sa1",
                region="eastus",
                data_tier=DataTier.TIER1_NATIVE,
            ),
        )
        message_body = finding.model_dump_json()

        card = await worker.process_message(message_body)

        assert card is not None
        assert isinstance(card, RemediationCard)
        mock_ai_engine.generate.assert_awaited_once()
        mock_db.save_remediation_card.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_ai_worker_invalid_json(
        self,
        mock_ai_engine: AsyncMock,
        mock_db: MagicMock,
    ) -> None:
        """Test AI worker handles invalid JSON gracefully."""
        worker = AIWorker(ai_engine=mock_ai_engine, db=mock_db)

        card = await worker.process_message("not valid json{{{")
        assert card is None
        mock_ai_engine.generate.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_ai_worker_ai_failure(
        self,
        mock_db: MagicMock,
    ) -> None:
        """Test AI worker handles AI engine failure."""
        from cloudguardiq.ai.remediation_engine import AIEngineError

        ai_engine = AsyncMock()
        ai_engine.generate.side_effect = AIEngineError("AI failed")

        worker = AIWorker(ai_engine=ai_engine, db=mock_db)

        finding = FindingResult(
            rule_id="TEST-001",
            severity=Severity.HIGH,
            description="test",
        )
        card = await worker.process_message(finding.model_dump_json())
        assert card is None


# ------------------------------------------------------------------
# API endpoint tests
# ------------------------------------------------------------------


class TestAPIEndpoints:
    """Tests for the FastAPI endpoints."""

    @pytest.mark.asyncio
    async def test_api_trigger_endpoint_returns_scan_id(self) -> None:
        """Test POST /scan/trigger returns a scan_id."""
        from httpx import ASGITransport, AsyncClient

        from cloudguardiq.api.auth import TokenPayload, verify_token
        from cloudguardiq.api.main import app

        async def _no_auth() -> TokenPayload:
            return TokenPayload(sub="test-user", tid="test-tenant")

        app.dependency_overrides[verify_token] = _no_auth
        if subs_module._repository is not None:
            await subs_module._repository.upsert(
                SubscriptionRecord(tenant_id="test-tenant", subscription_id="sub-test"),
            )
        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/scan/trigger",
                    json={"subscription_id": "sub-test"},
                )

            assert response.status_code == 200
            data = response.json()
            assert "scan_id" in data
            assert data["status"] == "queued"
        finally:
            app.dependency_overrides.pop(verify_token, None)

    @pytest.mark.asyncio
    async def test_scan_status_not_found(self) -> None:
        """Test GET /scan/{scan_id}/status returns 404 when not found."""
        from httpx import ASGITransport, AsyncClient

        from cloudguardiq.api.auth import TokenPayload, verify_token
        from cloudguardiq.api.main import app

        async def _no_auth() -> TokenPayload:
            return TokenPayload(sub="test-user", tid="test-tenant")

        app.dependency_overrides[verify_token] = _no_auth
        if subs_module._repository is not None:
            await subs_module._repository.upsert(
                SubscriptionRecord(tenant_id="test-tenant", subscription_id="sub-test"),
            )
        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get("/scan/nonexistent/status")

            assert response.status_code == 404
        finally:
            app.dependency_overrides.pop(verify_token, None)


# ------------------------------------------------------------------
# ScanResult model tests
# ------------------------------------------------------------------


class TestScanResult:
    """Tests for the ScanResult model."""

    def test_scan_result_defaults(self) -> None:
        """Test ScanResult has correct defaults."""
        result = ScanResult(subscription_id="sub-test")
        assert result.subscription_id == "sub-test"
        assert result.resources_scanned == 0
        assert result.findings_count == 0
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.total_waste_usd == 0.0
        assert result.scan_id  # auto-generated
        assert result.started_at  # auto-generated
