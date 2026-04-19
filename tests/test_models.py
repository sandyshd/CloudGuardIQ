"""Tests for core models and enums (legacy test file)."""

from __future__ import annotations

from cloudguardiq.core.enums import (
    CloudProvider,
    DataTier,
    FindingCategory,
    RemediationStatus,
    Severity,
)
from cloudguardiq.core.models import (
    FindingResult,
    RemediationCard,
    ResourceSnapshot,
    ScanRequest,
    ScanResponse,
)


class TestEnums:
    def test_data_tier_values(self) -> None:
        assert DataTier.TIER1_NATIVE == "TIER1_NATIVE"
        assert DataTier.TIER2_FREE_CSPM == "TIER2_FREE_CSPM"
        assert DataTier.TIER3_PAID == "TIER3_PAID"

    def test_severity_values(self) -> None:
        assert len(Severity) == 5
        assert Severity.CRITICAL == "CRITICAL"

    def test_finding_category_values(self) -> None:
        assert FindingCategory.SECURITY == "SECURITY"
        assert FindingCategory.COST == "COST"

    def test_remediation_status_values(self) -> None:
        assert RemediationStatus.PENDING == "PENDING"
        assert RemediationStatus.APPLIED == "APPLIED"

    def test_cloud_provider(self) -> None:
        assert CloudProvider.AZURE == "AZURE"


class TestResourceSnapshot:
    def test_create_snapshot(self, storage_snapshot: ResourceSnapshot) -> None:
        assert storage_snapshot.resource_name == "sa1"
        assert storage_snapshot.data_tier == DataTier.TIER1_NATIVE
        assert isinstance(storage_snapshot.id, str)

    def test_snapshot_defaults(self) -> None:
        snap = ResourceSnapshot(
            subscription_id="sub-1",
            resource_group="rg",
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="test",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
        )
        assert snap.cost_monthly == 0.0
        assert snap.tags == {}
        assert snap.config == {}
        assert snap.provider == CloudProvider.AZURE

    def test_snapshot_serialization(self, storage_snapshot: ResourceSnapshot) -> None:
        data = storage_snapshot.model_dump()
        assert "subscription_id" in data
        assert "data_tier" in data
        restored = ResourceSnapshot.model_validate(data)
        assert restored.resource_name == storage_snapshot.resource_name


class TestFindingResult:
    def test_create_finding(self, storage_snapshot: ResourceSnapshot) -> None:
        finding = FindingResult(
            snapshot_id=storage_snapshot.id,
            rule_id="TEST_RULE",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            category=FindingCategory.SECURITY,
            resource_id=storage_snapshot.resource_id,
            resource_type=storage_snapshot.resource_type,
            resource_name=storage_snapshot.resource_name,
        )
        assert finding.rule_id == "TEST_RULE"
        assert finding.severity == Severity.HIGH

    def test_finding_json(self, storage_snapshot: ResourceSnapshot) -> None:
        finding = FindingResult(
            snapshot_id=storage_snapshot.id,
            rule_id="TEST",
            title="T",
            description="D",
            severity=Severity.LOW,
            category=FindingCategory.COST,
            resource_id="r",
            resource_type="t",
            resource_name="n",
        )
        json_str = finding.model_dump_json()
        assert "TEST" in json_str


class TestRemediationCard:
    def test_create_card(self) -> None:
        from uuid import uuid4

        card = RemediationCard(
            finding_id=uuid4(),
            summary="Fix it",
            explanation="Do this",
            terraform_code='resource "azurerm_storage_account" {}',
        )
        assert card.status == RemediationStatus.PENDING
        assert card.terraform_code != ""


class TestAPIModels:
    def test_scan_request(self) -> None:
        req = ScanRequest(subscription_id="sub-1")
        assert req.include_cost is True

    def test_scan_response(self) -> None:
        resp = ScanResponse(
            subscription_id="sub-1",
            snapshots_count=10,
            findings_count=3,
        )
        assert resp.findings == []
