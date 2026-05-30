"""Tests for scan persistence to Cosmos DB."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from cloudguardiq.api.main import app
from cloudguardiq.core.enums import (
    CloudProvider,
    DataTier,
    FindingType,
    Severity,
)
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


@pytest.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestScanPersistence:
    @pytest.mark.asyncio
    async def test_scan_calls_persist_when_repo_available(
        self, client: AsyncClient,
    ) -> None:
        """POST /scan should persist findings to Cosmos when repo exists."""
        mock_repo = AsyncMock()
        mock_repo.save_snapshot = AsyncMock(return_value="snap-id")
        mock_repo.save_finding = AsyncMock(return_value="finding-id")
        mock_repo.save_scan_result = AsyncMock()

        # Mock credential to None so no real Azure calls are made
        with (
            patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
            patch(
                "cloudguardiq.api.main.scan_subscription.__module__",
                create=True,
            ),
            patch(
                "azure.identity.DefaultAzureCredential",
                side_effect=Exception("no creds"),
            ),
        ):
            response = await client.post(
                "/scan",
                json={"subscription_id": "sub-123"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["subscription_id"] == "sub-123"
        # scan_result should always be saved
        mock_repo.save_scan_result.assert_called_once()
        scan_doc = mock_repo.save_scan_result.call_args[0][0]
        assert scan_doc["status"] == "completed"
        assert scan_doc["subscription_id"] == "sub-123"

    @pytest.mark.asyncio
    async def test_scan_persists_snapshots_and_findings(
        self, client: AsyncClient,
    ) -> None:
        """POST /scan should save each snapshot and finding individually."""
        mock_repo = AsyncMock()
        mock_repo.save_snapshot = AsyncMock(return_value="snap-id")
        mock_repo.save_finding = AsyncMock(return_value="finding-id")
        mock_repo.save_scan_result = AsyncMock()

        snap = ResourceSnapshot(
            subscription_id="sub-test",
            resource_group="rg1",
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="sa-insecure",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
            config={
                "supportsHttpsTrafficOnly": False,
                "allowBlobPublicAccess": True,
            },
        )
        mock_adapter = AsyncMock()
        mock_adapter.list_resources = AsyncMock(return_value=[snap])
        mock_adapter.enrich_with_defender = AsyncMock(return_value=[snap])

        with (
            patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
            patch(
                "azure.identity.DefaultAzureCredential",
                return_value=MagicMock(),
            ),
            patch(
                "cloudguardiq.api.main.AzureAdapter",
                return_value=mock_adapter,
            ),
        ):
            response = await client.post(
                "/scan",
                json={"subscription_id": "sub-test"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["snapshots_count"] == 1
        assert data["findings_count"] >= 1

        # Snapshots persisted
        assert mock_repo.save_snapshot.call_count == 1
        # Findings persisted
        assert mock_repo.save_finding.call_count >= 1
        # Scan summary persisted
        mock_repo.save_scan_result.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_without_repo_still_returns(
        self, client: AsyncClient,
    ) -> None:
        """POST /scan should work without Cosmos DB (no persistence)."""
        with (
            patch("cloudguardiq.api.main.get_repo", return_value=None),
            patch(
                "azure.identity.DefaultAzureCredential",
                side_effect=Exception("no creds"),
            ),
        ):
            response = await client.post(
                "/scan",
                json={"subscription_id": "sub-456"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["subscription_id"] == "sub-456"


class TestDegradedScanPreservesFindings:
    @pytest.mark.asyncio
    async def test_zero_resource_scan_does_not_autoresolve(
        self, client: AsyncClient,
    ) -> None:
        """A degraded scan that enumerates 0 resources must NOT auto-resolve.

        If the adapter cannot enumerate resources (e.g. missing Reader role
        or a transient Azure error), the scan yields 0 findings. Running the
        unseen-findings auto-resolve sweep in that case would wrongly flip
        every previously-OPEN finding to RESOLVED and blank the dashboard.
        """
        mock_repo = AsyncMock()
        mock_repo.save_snapshot = AsyncMock(return_value="snap-id")
        mock_repo.save_finding = AsyncMock(return_value="finding-id")
        mock_repo.save_scan_result = AsyncMock()
        mock_repo.mark_unseen_findings_resolved = AsyncMock(return_value=0)

        mock_adapter = AsyncMock()
        mock_adapter.list_resources = AsyncMock(return_value=[])
        mock_adapter.enrich_with_defender = AsyncMock(return_value=[])
        mock_adapter.fetch_policy_findings = AsyncMock(return_value=[])

        with (
            patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
            patch(
                "azure.identity.DefaultAzureCredential",
                return_value=MagicMock(),
            ),
            patch(
                "cloudguardiq.api.main.AzureAdapter",
                return_value=mock_adapter,
            ),
        ):
            response = await client.post(
                "/scan",
                json={"subscription_id": "sub-degraded"},
            )

        assert response.status_code == 200
        # The auto-resolve sweep must be skipped for a 0-resource scan.
        mock_repo.mark_unseen_findings_resolved.assert_not_called()


class TestGetFinding:
    @pytest.mark.asyncio
    async def test_get_finding_from_db(
        self, client: AsyncClient,
    ) -> None:
        """GET /findings/{id} should query Cosmos when available."""
        snap = ResourceSnapshot(
            subscription_id="sub-123",
            resource_group="rg1",
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="sa1",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
        )
        finding = FindingResult(
            finding_id="test-finding-1",
            rule_id="STORAGE-001",
            rule_name="Storage HTTPS Only",
            severity=Severity.HIGH,
            resource_snapshot=snap,
            description="Test finding",
        )
        mock_repo = AsyncMock()
        mock_repo.get_finding = AsyncMock(return_value=finding)

        with patch("cloudguardiq.api.main.get_repo", return_value=mock_repo):
            response = await client.get("/findings/test-finding-1")

        assert response.status_code == 200
        data = response.json()
        assert data["finding_id"] == "test-finding-1"
        mock_repo.get_finding.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_finding_falls_back_to_demo(
        self, client: AsyncClient,
    ) -> None:
        """GET /findings/{id} falls back to demo data when DB empty."""
        # Get a valid demo finding ID first
        list_resp = await client.get("/findings")
        finding_id = list_resp.json()[0]["finding_id"]

        response = await client.get(f"/findings/{finding_id}")
        assert response.status_code == 200
        assert response.json()["finding_id"] == finding_id


class TestScanMergesPolicyFindings:
    @pytest.mark.asyncio
    async def test_scan_merges_azure_policy_findings(self) -> None:
        """POST /scan must ingest AZPOL- findings via fetch_policy_findings()."""
        transport = ASGITransport(app=app)
        mock_repo = AsyncMock()
        mock_repo.save_snapshot = AsyncMock(return_value="snap-id")
        mock_repo.save_finding = AsyncMock(return_value="finding-id")
        mock_repo.save_scan_result = AsyncMock()

        snap = ResourceSnapshot(
            subscription_id="sub-123",
            resource_group="rg1",
            resource_type="storage_account",
            resource_name="acct1",
            region="eastus",
            provider=CloudProvider.AZURE,
            data_tier=DataTier.TIER1_NATIVE,
        )
        azpol = FindingResult(
            finding_id="azpol-1",
            resource_snapshot=snap,
            rule_id="AZPOL-DenyHttpStorage",
            rule_name="DenyHttpStorage",
            severity=Severity.MEDIUM,
            finding_type=FindingType.COMPLIANCE,
            description="Non-compliant with assigned Azure Policy.",
            compliance_frameworks=["CIS_AZURE"],
        )

        mock_adapter = MagicMock()
        mock_adapter.list_resources = AsyncMock(return_value=[])
        mock_adapter.enrich_with_defender = AsyncMock(return_value=[])
        mock_adapter.fetch_policy_findings = AsyncMock(return_value=[azpol])

        with (
            patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
            patch("cloudguardiq.api.main.AzureAdapter", return_value=mock_adapter),
            patch("azure.identity.DefaultAzureCredential", return_value=MagicMock()),
        ):
            async with AsyncClient(
                transport=transport, base_url="http://test"
            ) as ac:
                response = await ac.post(
                    "/scan", json={"subscription_id": "sub-123"}
                )

        assert response.status_code == 200
        data = response.json()
        assert data["findings_count"] == 1
        assert data["findings"][0]["rule_id"] == "AZPOL-DenyHttpStorage"
        mock_adapter.fetch_policy_findings.assert_awaited_once()

