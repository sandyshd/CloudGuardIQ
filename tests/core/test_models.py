"""Tests for core models and enums -- full JSON round-trip and 100% coverage."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from cloudguardiq.core.enums import (
    CloudProvider,
    DataTier,
    FindingCategory,
    FindingType,
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

# ── Enum tests ──────────────────────────────────────────────────────


class TestCloudProvider:
    def test_values(self) -> None:
        assert CloudProvider.AZURE == "AZURE"
        assert CloudProvider.AWS == "AWS"
        assert CloudProvider.GCP == "GCP"
        assert CloudProvider.TERRAFORM == "TERRAFORM"

    def test_member_count(self) -> None:
        assert len(CloudProvider) == 4


class TestDataTier:
    def test_values(self) -> None:
        assert DataTier.TIER1_NATIVE == "TIER1_NATIVE"
        assert DataTier.TIER2_FREE_CSPM == "TIER2_FREE_CSPM"
        assert DataTier.TIER3_PAID == "TIER3_PAID"

    def test_member_count(self) -> None:
        assert len(DataTier) == 3


class TestSeverity:
    def test_values(self) -> None:
        assert Severity.CRITICAL == "CRITICAL"
        assert Severity.HIGH == "HIGH"
        assert Severity.MEDIUM == "MEDIUM"
        assert Severity.LOW == "LOW"
        assert Severity.INFORMATIONAL == "INFORMATIONAL"

    def test_member_count(self) -> None:
        assert len(Severity) == 5


class TestFindingType:
    def test_values(self) -> None:
        assert FindingType.SECURITY == "SECURITY"
        assert FindingType.FINOPS == "FINOPS"
        assert FindingType.COMPLIANCE == "COMPLIANCE"

    def test_member_count(self) -> None:
        assert len(FindingType) == 3


class TestLegacyEnums:
    def test_finding_category(self) -> None:
        assert FindingCategory.SECURITY == "SECURITY"
        assert FindingCategory.COST == "COST"

    def test_remediation_status(self) -> None:
        assert RemediationStatus.PENDING == "PENDING"
        assert RemediationStatus.APPLIED == "APPLIED"


# ── ResourceSnapshot tests ──────────────────────────────────────────


class TestResourceSnapshot:
    @pytest.fixture()
    def snapshot(self) -> ResourceSnapshot:
        return ResourceSnapshot(
            provider=CloudProvider.AZURE,
            subscription_id="sub-123",
            resource_group="rg1",
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="sa1",
            region="eastus",
            config={"supportsHttpsTrafficOnly": True},
            cost_monthly=12.50,
            tags={"env": "prod"},
            data_tier=DataTier.TIER1_NATIVE,
        )

    def test_auto_id(self, snapshot: ResourceSnapshot) -> None:
        assert snapshot.id == "azure/storageaccounts/sub-123/rg1/sa1"

    def test_build_id_classmethod(self) -> None:
        result = ResourceSnapshot.build_id(
            CloudProvider.AZURE,
            "Microsoft.Storage/storageAccounts",
            "SUB-1",
            "RG",
            "SA",
        )
        assert result == "azure/storageaccounts/sub-1/rg/sa"

    def test_build_id_no_slash(self) -> None:
        result = ResourceSnapshot.build_id(
            CloudProvider.AWS, "s3_bucket", "acc-1", "global", "mybucket"
        )
        assert result == "aws/s3_bucket/acc-1/global/mybucket"

    def test_raw_hash_auto(self, snapshot: ResourceSnapshot) -> None:
        assert len(snapshot.raw_hash) == 64  # SHA256 hex digest

    def test_raw_hash_explicit(self) -> None:
        snap = ResourceSnapshot(
            subscription_id="s",
            resource_group="r",
            resource_type="t",
            resource_name="n",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
            raw_hash="abc123",
        )
        assert snap.raw_hash == "abc123"

    def test_explicit_id(self) -> None:
        snap = ResourceSnapshot(
            id="custom/id",
            subscription_id="s",
            resource_group="r",
            resource_type="t",
            resource_name="n",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
        )
        assert snap.id == "custom/id"

    def test_defaults(self) -> None:
        snap = ResourceSnapshot(
            subscription_id="s",
            resource_group="rg",
            resource_type="t",
            resource_name="n",
            region="westus",
            data_tier=DataTier.TIER2_FREE_CSPM,
        )
        assert snap.provider == CloudProvider.AZURE
        assert snap.cost_monthly == 0.0
        assert snap.tags == {}
        assert snap.config == {}
        assert isinstance(snap.captured_at, datetime)

    def test_json_round_trip(self, snapshot: ResourceSnapshot) -> None:
        json_str = snapshot.model_dump_json()
        data = json.loads(json_str)
        restored = ResourceSnapshot.model_validate(data)
        assert restored.id == snapshot.id
        assert restored.subscription_id == snapshot.subscription_id
        assert restored.config == snapshot.config
        assert restored.data_tier == snapshot.data_tier
        assert restored.cost_monthly == snapshot.cost_monthly

    def test_dict_round_trip(self, snapshot: ResourceSnapshot) -> None:
        data = snapshot.model_dump()
        restored = ResourceSnapshot.model_validate(data)
        assert restored.resource_name == snapshot.resource_name

    def test_backward_compat_properties(self, snapshot: ResourceSnapshot) -> None:
        assert snapshot.resource_id == snapshot.id
        assert snapshot.location == snapshot.region
        assert snapshot.properties is snapshot.config
        assert snapshot.scanned_at == snapshot.captured_at

    def test_frozen_false(self, snapshot: ResourceSnapshot) -> None:
        snapshot.cost_monthly = 99.0
        assert snapshot.cost_monthly == 99.0


# ── FindingResult tests ─────────────────────────────────────────────


class TestFindingResult:
    @pytest.fixture()
    def snapshot(self) -> ResourceSnapshot:
        return ResourceSnapshot(
            subscription_id="sub-1",
            resource_group="rg",
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="sa",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
        )

    @pytest.fixture()
    def finding(self, snapshot: ResourceSnapshot) -> FindingResult:
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id="STOR-001",
            rule_name="Storage HTTPS enforcement",
            severity=Severity.HIGH,
            finding_type=FindingType.SECURITY,
            description="HTTPS not enforced",
            evidence={"supportsHttpsTrafficOnly": False},
            compliance_frameworks=["CIS_3.1", "SOC2_CC6.1"],
            waste_monthly_usd=0.0,
        )

    def test_finding_id_auto(self, finding: FindingResult) -> None:
        assert len(finding.finding_id) == 36  # UUID string

    def test_fields(self, finding: FindingResult) -> None:
        assert finding.rule_id == "STOR-001"
        assert finding.severity == Severity.HIGH
        assert finding.finding_type == FindingType.SECURITY
        assert finding.resource_snapshot is not None
        assert finding.compliance_frameworks == ["CIS_3.1", "SOC2_CC6.1"]

    def test_compute_priority_score_defaults(self, finding: FindingResult) -> None:
        score = finding.compute_priority_score()
        # alpha=0.5 * 80(HIGH) + beta=0.3 * 0(waste) + gamma=0.2 * 50(2*25)
        expected = 0.5 * 80 + 0.3 * 0 + 0.2 * 50
        assert score == expected
        assert finding.priority_score == expected

    def test_compute_priority_score_custom_weights(self) -> None:
        f = FindingResult(
            rule_id="X",
            severity=Severity.CRITICAL,
            waste_monthly_usd=200.0,
            compliance_frameworks=["A", "B", "C", "D", "E"],
        )
        score = f.compute_priority_score(alpha=0.6, beta=0.2, gamma=0.2)
        # severity=100, cost capped at 100, compliance capped at 100
        expected = round(0.6 * 100 + 0.2 * 100 + 0.2 * 100, 2)
        assert score == expected

    def test_compute_priority_informational(self) -> None:
        f = FindingResult(rule_id="X", severity=Severity.INFORMATIONAL)
        score = f.compute_priority_score()
        assert score == 0.5 * 20  # 10.0

    def test_json_round_trip(self, finding: FindingResult) -> None:
        json_str = finding.model_dump_json()
        data = json.loads(json_str)
        restored = FindingResult.model_validate(data)
        assert restored.finding_id == finding.finding_id
        assert restored.rule_id == finding.rule_id
        assert restored.severity == finding.severity
        assert restored.resource_snapshot is not None
        assert restored.resource_snapshot.id == finding.resource_snapshot.id

    def test_dict_round_trip(self, finding: FindingResult) -> None:
        data = finding.model_dump()
        restored = FindingResult.model_validate(data)
        assert restored.rule_name == finding.rule_name

    def test_id_property(self, finding: FindingResult) -> None:
        assert finding.id == finding.finding_id

    def test_legacy_title_to_rule_name(self) -> None:
        f = FindingResult(
            rule_id="T",
            title="My Title",
            severity=Severity.LOW,
        )
        assert f.rule_name == "My Title"

    def test_legacy_category_cost(self) -> None:
        f = FindingResult(
            rule_id="T",
            severity=Severity.LOW,
            category=FindingCategory.COST,
        )
        assert f.finding_type == FindingType.FINOPS

    def test_legacy_category_compliance(self) -> None:
        f = FindingResult(
            rule_id="T",
            severity=Severity.LOW,
            category=FindingCategory.COMPLIANCE,
        )
        assert f.finding_type == FindingType.COMPLIANCE

    def test_legacy_category_security(self) -> None:
        f = FindingResult(
            rule_id="T",
            severity=Severity.LOW,
            category=FindingCategory.SECURITY,
        )
        assert f.finding_type == FindingType.SECURITY

    def test_frozen_false(self, finding: FindingResult) -> None:
        finding.description = "changed"
        assert finding.description == "changed"


# ── RemediationCard tests ───────────────────────────────────────────


class TestRemediationCard:
    @pytest.fixture()
    def finding(self) -> FindingResult:
        return FindingResult(
            rule_id="STOR-001",
            rule_name="HTTPS",
            severity=Severity.HIGH,
        )

    @pytest.fixture()
    def card(self, finding: FindingResult) -> RemediationCard:
        return RemediationCard(
            finding_result=finding,
            narrative="Enable HTTPS on the storage account.",
            terraform_fix=(
                'resource "azurerm_storage_account" "sa"'
                " { enable_https_traffic_only = true }"
            ),
            cli_fix="az storage account update --https-only true",
            confidence_qualifier="High confidence (Tier 1 data)",
            estimated_savings_usd=0.0,
            model_version="gpt-5.1-2025-11-13",
        )

    def test_card_id_auto(self, card: RemediationCard) -> None:
        assert len(card.card_id) == 36

    def test_fields(self, card: RemediationCard) -> None:
        assert card.narrative.startswith("Enable")
        assert "azurerm" in card.terraform_fix
        assert card.model_version.startswith("gpt-5.1")
        assert card.finding_result is not None

    def test_json_round_trip(self, card: RemediationCard) -> None:
        json_str = card.model_dump_json()
        data = json.loads(json_str)
        restored = RemediationCard.model_validate(data)
        assert restored.card_id == card.card_id
        assert restored.narrative == card.narrative
        assert restored.terraform_fix == card.terraform_fix
        assert restored.finding_result is not None

    def test_dict_round_trip(self, card: RemediationCard) -> None:
        data = card.model_dump()
        restored = RemediationCard.model_validate(data)
        assert restored.cli_fix == card.cli_fix

    def test_id_property(self, card: RemediationCard) -> None:
        assert card.id == card.card_id

    def test_legacy_summary_to_narrative(self) -> None:
        card = RemediationCard(summary="Fix it")
        assert card.narrative == "Fix it"

    def test_legacy_terraform_code_to_fix(self) -> None:
        card = RemediationCard(terraform_code='resource "x" {}')
        assert card.terraform_fix == 'resource "x" {}'

    def test_legacy_status(self) -> None:
        card = RemediationCard()
        assert card.status == RemediationStatus.PENDING

    def test_frozen_false(self, card: RemediationCard) -> None:
        card.narrative = "Updated"
        assert card.narrative == "Updated"


# ── ScanRequest / ScanResponse tests ────────────────────────────────


class TestScanRequest:
    def test_defaults(self) -> None:
        req = ScanRequest(subscription_id="sub-1")
        assert req.include_cost is True

    def test_json_round_trip(self) -> None:
        req = ScanRequest(subscription_id="s", include_cost=False)
        restored = ScanRequest.model_validate_json(req.model_dump_json())
        assert restored.subscription_id == "s"
        assert restored.include_cost is False


class TestScanResponse:
    def test_defaults(self) -> None:
        resp = ScanResponse(subscription_id="s", snapshots_count=5, findings_count=2)
        assert resp.findings == []

    def test_json_round_trip(self) -> None:
        resp = ScanResponse(subscription_id="s", snapshots_count=1, findings_count=0)
        restored = ScanResponse.model_validate_json(resp.model_dump_json())
        assert restored.subscription_id == "s"


# ── Edge case tests ─────────────────────────────────────────────────


def _make_snapshot(**overrides: Any) -> ResourceSnapshot:
    """Factory helper for edge-case snapshot creation."""
    defaults: dict[str, Any] = {
        "subscription_id": "sub-edge",
        "resource_group": "rg-edge",
        "resource_type": "Microsoft.Storage/storageAccounts",
        "resource_name": "edgesa",
        "region": "eastus",
        "data_tier": DataTier.TIER1_NATIVE,
    }
    defaults.update(overrides)
    return ResourceSnapshot(**defaults)


class TestResourceSnapshotEdgeCases:
    def test_empty_config_produces_deterministic_hash(self) -> None:
        snap_a = _make_snapshot()
        snap_b = _make_snapshot()
        assert snap_a.raw_hash == snap_b.raw_hash
        assert len(snap_a.raw_hash) == 64

    def test_different_configs_produce_different_hashes(self) -> None:
        snap_a = _make_snapshot(config={"a": 1})
        snap_b = _make_snapshot(config={"a": 2})
        assert snap_a.raw_hash != snap_b.raw_hash

    def test_config_hash_is_order_independent(self) -> None:
        snap_a = _make_snapshot(config={"z": 1, "a": 2})
        snap_b = _make_snapshot(config={"a": 2, "z": 1})
        assert snap_a.raw_hash == snap_b.raw_hash

    def test_empty_resource_group(self) -> None:
        snap = _make_snapshot(resource_group="")
        assert "//" in snap.id  # two consecutive slashes for empty segment

    def test_build_id_preserves_case_lowered(self) -> None:
        snap = _make_snapshot(
            resource_name="MyMixedCaseResource",
            resource_group="RG-UPPER",
            subscription_id="SUB-UPPER",
        )
        assert snap.id == "azure/storageaccounts/sub-upper/rg-upper/mymixedcaseresource"

    def test_deeply_nested_config(self) -> None:
        nested = {"l1": {"l2": {"l3": {"l4": [1, 2, {"l5": True}]}}}}
        snap = _make_snapshot(config=nested)
        assert snap.config["l1"]["l2"]["l3"]["l4"][2]["l5"] is True
        assert len(snap.raw_hash) == 64

    def test_special_characters_in_tags(self) -> None:
        snap = _make_snapshot(tags={"env": "prod/staging", "team": "a&b", "emoji": "✓"})
        data = snap.model_dump()
        restored = ResourceSnapshot.model_validate(data)
        assert restored.tags["emoji"] == "✓"
        assert restored.tags["env"] == "prod/staging"

    def test_zero_cost(self) -> None:
        snap = _make_snapshot(cost_monthly=0.0)
        assert snap.cost_monthly == 0.0

    def test_very_large_cost(self) -> None:
        snap = _make_snapshot(cost_monthly=999_999.99)
        restored = ResourceSnapshot.model_validate_json(snap.model_dump_json())
        assert restored.cost_monthly == 999_999.99

    def test_all_providers(self) -> None:
        for provider in CloudProvider:
            snap = _make_snapshot(provider=provider)
            assert snap.id.startswith(provider.value.lower() + "/")

    def test_all_data_tiers(self) -> None:
        for tier in DataTier:
            snap = _make_snapshot(data_tier=tier)
            assert snap.data_tier == tier

    def test_captured_at_is_timezone_aware(self) -> None:
        snap = _make_snapshot()
        assert snap.captured_at.tzinfo is not None

    def test_explicit_captured_at_preserved(self) -> None:
        ts = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        snap = _make_snapshot(captured_at=ts)
        assert snap.captured_at == ts

    def test_missing_required_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            ResourceSnapshot(
                subscription_id="s",
                resource_group="rg",
                resource_type="t",
                resource_name="n",
                # missing region and data_tier
            )  # type: ignore[call-arg]

    def test_multiple_slashes_in_resource_type(self) -> None:
        snap = _make_snapshot(
            resource_type="Microsoft.Network/virtualNetworks/subnets",
        )
        # build_id takes last segment after final "/"
        assert "subnets" in snap.id


class TestFindingResultEdgeCases:
    def test_empty_compliance_frameworks(self) -> None:
        f = FindingResult(rule_id="X", severity=Severity.HIGH)
        score = f.compute_priority_score()
        # gamma * 0 = 0
        assert score == 0.5 * 80

    def test_single_compliance_framework(self) -> None:
        f = FindingResult(
            rule_id="X",
            severity=Severity.LOW,
            compliance_frameworks=["CIS_1.0"],
        )
        score = f.compute_priority_score()
        assert score == 0.5 * 40 + 0.3 * 0 + 0.2 * 25

    def test_compliance_score_capped_at_100(self) -> None:
        f = FindingResult(
            rule_id="X",
            severity=Severity.MEDIUM,
            compliance_frameworks=[f"FW_{i}" for i in range(10)],
        )
        score = f.compute_priority_score()
        # 10 * 25 = 250, capped at 100
        assert score == 0.5 * 60 + 0.3 * 0 + 0.2 * 100

    def test_waste_capped_at_100(self) -> None:
        f = FindingResult(
            rule_id="X",
            severity=Severity.LOW,
            waste_monthly_usd=5000.0,
        )
        score = f.compute_priority_score()
        assert score == 0.5 * 40 + 0.3 * 100 + 0.2 * 0

    def test_zero_waste(self) -> None:
        f = FindingResult(rule_id="X", severity=Severity.LOW, waste_monthly_usd=0.0)
        score = f.compute_priority_score()
        assert score == 0.5 * 40

    def test_priority_score_all_zeros(self) -> None:
        f = FindingResult(rule_id="X", severity=Severity.INFORMATIONAL)
        score = f.compute_priority_score(alpha=0.0, beta=0.0, gamma=0.0)
        assert score == 0.0

    def test_priority_score_all_max(self) -> None:
        f = FindingResult(
            rule_id="X",
            severity=Severity.CRITICAL,
            waste_monthly_usd=999.0,
            compliance_frameworks=["A", "B", "C", "D", "E"],
        )
        score = f.compute_priority_score(alpha=1.0, beta=1.0, gamma=1.0)
        assert score == 100.0 + 100.0 + 100.0

    def test_priority_score_idempotent(self) -> None:
        f = FindingResult(rule_id="X", severity=Severity.HIGH, waste_monthly_usd=50.0)
        first = f.compute_priority_score()
        second = f.compute_priority_score()
        assert first == second

    def test_finding_no_snapshot(self) -> None:
        f = FindingResult(rule_id="X", severity=Severity.LOW)
        assert f.resource_snapshot is None
        data = f.model_dump()
        restored = FindingResult.model_validate(data)
        assert restored.resource_snapshot is None

    def test_empty_evidence(self) -> None:
        f = FindingResult(rule_id="X", severity=Severity.LOW, evidence={})
        assert f.evidence == {}

    def test_complex_evidence_round_trip(self) -> None:
        evidence = {
            "ports": [22, 3389],
            "nested": {"deep": True},
            "text": "some\nnewlines",
        }
        f = FindingResult(rule_id="X", severity=Severity.LOW, evidence=evidence)
        restored = FindingResult.model_validate_json(f.model_dump_json())
        assert restored.evidence["ports"] == [22, 3389]
        assert restored.evidence["nested"]["deep"] is True

    def test_each_severity_has_score(self) -> None:
        for sev in Severity:
            f = FindingResult(rule_id="X", severity=sev)
            score = f.compute_priority_score()
            assert score > 0

    def test_legacy_fields_excluded_from_dump(self) -> None:
        f = FindingResult(
            rule_id="X",
            severity=Severity.LOW,
            snapshot_id="old-id",
            title="Old Title",
            category=FindingCategory.COST,
            resource_id="rid",
            recommended_action="do something",
        )
        data = f.model_dump()
        assert "snapshot_id" not in data
        assert "title" not in data
        assert "category" not in data
        assert "resource_id" not in data
        assert "recommended_action" not in data

    def test_legacy_title_does_not_overwrite_explicit_rule_name(self) -> None:
        f = FindingResult(
            rule_id="X",
            severity=Severity.LOW,
            rule_name="Explicit Name",
            title="Should Not Override",
        )
        assert f.rule_name == "Explicit Name"

    def test_legacy_category_does_not_overwrite_explicit_finding_type(self) -> None:
        f = FindingResult(
            rule_id="X",
            severity=Severity.LOW,
            finding_type=FindingType.COMPLIANCE,
            category=FindingCategory.COST,
        )
        # finding_type was explicitly set to non-SECURITY, so category bridge skipped
        assert f.finding_type == FindingType.COMPLIANCE

    def test_detected_at_is_timezone_aware(self) -> None:
        f = FindingResult(rule_id="X", severity=Severity.LOW)
        assert f.detected_at.tzinfo is not None

    def test_unique_finding_ids(self) -> None:
        ids = {
            FindingResult(rule_id="X", severity=Severity.LOW).finding_id
            for _ in range(50)
        }
        assert len(ids) == 50


class TestRemediationCardEdgeCases:
    def test_no_finding_result(self) -> None:
        card = RemediationCard()
        assert card.finding_result is None
        data = card.model_dump()
        restored = RemediationCard.model_validate(data)
        assert restored.finding_result is None

    def test_empty_strings(self) -> None:
        card = RemediationCard()
        assert card.narrative == ""
        assert card.terraform_fix == ""
        assert card.cli_fix == ""
        assert card.confidence_qualifier == ""
        assert card.model_version == ""

    def test_legacy_fields_excluded_from_dump(self) -> None:
        card = RemediationCard(
            summary="S",
            explanation="E",
            risk_if_ignored="R",
            terraform_code="T",
            manual_steps=["step1"],
        )
        data = card.model_dump()
        assert "summary" not in data
        assert "explanation" not in data
        assert "risk_if_ignored" not in data
        assert "terraform_code" not in data
        assert "manual_steps" not in data
        assert "status" not in data

    def test_legacy_summary_does_not_overwrite_explicit_narrative(self) -> None:
        card = RemediationCard(
            narrative="Explicit Narrative",
            summary="Should Not Override",
        )
        assert card.narrative == "Explicit Narrative"

    def test_legacy_terraform_code_does_not_overwrite_explicit_fix(self) -> None:
        card = RemediationCard(
            terraform_fix="explicit fix",
            terraform_code="should not override",
        )
        assert card.terraform_fix == "explicit fix"

    def test_multiline_terraform_fix(self) -> None:
        hcl = (
            'resource "azurerm_storage_account" "sa" {\n'
            '  name                     = "example"\n'
            "  enable_https_traffic_only = true\n"
            "}"
        )
        card = RemediationCard(terraform_fix=hcl)
        restored = RemediationCard.model_validate_json(card.model_dump_json())
        assert restored.terraform_fix == hcl

    def test_unique_card_ids(self) -> None:
        ids = {RemediationCard().card_id for _ in range(50)}
        assert len(ids) == 50

    def test_generated_at_is_timezone_aware(self) -> None:
        card = RemediationCard()
        assert card.generated_at.tzinfo is not None

    def test_full_chain_snapshot_finding_card_round_trip(self) -> None:
        snap = _make_snapshot(config={"https": False}, cost_monthly=42.0)
        finding = FindingResult(
            resource_snapshot=snap,
            rule_id="STOR-001",
            rule_name="HTTPS",
            severity=Severity.CRITICAL,
            finding_type=FindingType.SECURITY,
            waste_monthly_usd=42.0,
            compliance_frameworks=["CIS_3.1"],
        )
        finding.compute_priority_score()
        card = RemediationCard(
            finding_result=finding,
            narrative="Enable HTTPS",
            terraform_fix='resource "x" {}',
            cli_fix="az ...",
            model_version="gpt-5.1-2025-11-13",
            estimated_savings_usd=42.0,
        )
        json_str = card.model_dump_json()
        restored = RemediationCard.model_validate_json(json_str)
        assert restored.finding_result is not None
        assert restored.finding_result.resource_snapshot is not None
        assert restored.finding_result.resource_snapshot.config == {"https": False}
        assert restored.finding_result.priority_score == finding.priority_score
        assert restored.estimated_savings_usd == 42.0


class TestScanResponseEdgeCases:
    def test_response_with_findings(self) -> None:
        f = FindingResult(rule_id="X", severity=Severity.LOW)
        resp = ScanResponse(
            subscription_id="s",
            snapshots_count=1,
            findings_count=1,
            findings=[f],
        )
        json_str = resp.model_dump_json()
        restored = ScanResponse.model_validate_json(json_str)
        assert len(restored.findings) == 1
        assert restored.findings[0].rule_id == "X"

    def test_response_zero_counts(self) -> None:
        resp = ScanResponse(subscription_id="s", snapshots_count=0, findings_count=0)
        assert resp.snapshots_count == 0
        assert resp.findings_count == 0
        assert resp.findings == []
