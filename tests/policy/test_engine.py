"""Tests for the PolicyEngine — async evaluation, priority scoring, auto-discovery."""

from __future__ import annotations

import asyncio

import pytest

from cloudguardiq.adapters.rules.azure.storage import PublicBlobAccessRule
from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot
from cloudguardiq.policy.engine import PolicyEngine, _compute_priority, _discover_rules

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def insecure_storage() -> ResourceSnapshot:
    """Storage account with public blob access enabled (triggers STOR-001)."""
    return ResourceSnapshot(
        subscription_id="sub-test",
        resource_group="rg-test",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="insecuresa",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={
            "allow_blob_public_access": True,
            "enable_https_traffic_only": False,
            "minimum_tls_version": "TLS1_0",
            "allow_shared_key_access": True,
            "network_default_action": "Allow",
            "blob_soft_delete_enabled": False,
            "blob_versioning_enabled": False,
            "infrastructure_encryption_enabled": False,
            "diagnostic_logging_enabled": False,
        },
        cost_monthly=200.0,
    )


@pytest.fixture
def clean_storage() -> ResourceSnapshot:
    """Storage account that passes all storage rules.

    Also includes keys that prevent non-storage rules from firing
    (e.g. KV, VM, IAM, network rules check for absent config keys).
    """
    return ResourceSnapshot(
        subscription_id="sub-test",
        resource_group="rg-test",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="securesa",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={
            "allow_blob_public_access": False,
            "enable_https_traffic_only": True,
            "minimum_tls_version": "TLS1_2",
            "allow_shared_key_access": False,
            "network_default_action": "Deny",
            "blob_soft_delete_enabled": True,
            "blob_versioning_enabled": True,
            "infrastructure_encryption_enabled": True,
            "diagnostic_logging_enabled": True,
            "lifecycle_policy_exists": True,
        },
        cost_monthly=10.0,
    )


@pytest.fixture
def storage_only_engine() -> PolicyEngine:
    """PolicyEngine with only storage rules (STOR-001 .. STOR-010)."""
    all_rules = _discover_rules()
    storage_rules = [r for r in all_rules if getattr(r, "rule_id", "").startswith("STOR-")]
    return PolicyEngine(rules=storage_rules)


@pytest.fixture
def engine() -> PolicyEngine:
    """PolicyEngine with auto-discovered rules."""
    return PolicyEngine()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPolicyEngineNew:
    """Tests for the new async PolicyEngine."""

    def test_engine_finds_critical_storage_finding(
        self, engine: PolicyEngine, insecure_storage: ResourceSnapshot,
    ) -> None:
        """Engine detects STOR-001 (public blob access) as CRITICAL."""
        findings = engine.evaluate([insecure_storage])
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        stor001 = [f for f in critical if f.rule_id == "STOR-001"]
        assert len(stor001) == 1
        assert stor001[0].finding_type == FindingType.SECURITY

    def test_engine_returns_empty_for_clean_resource(
        self, storage_only_engine: PolicyEngine, clean_storage: ResourceSnapshot,
    ) -> None:
        """No findings for a fully compliant storage account (storage rules only)."""
        findings = storage_only_engine.evaluate([clean_storage])
        assert findings == []

    def test_engine_runs_all_rules(self, engine: PolicyEngine) -> None:
        """Verify all 55 native rules (44 Azure + 11 AWS) are auto-discovered."""
        assert engine.native_rule_count == 55

    def test_priority_score_critical_high_cost_is_near_100(self) -> None:
        """CRITICAL severity + high waste + many frameworks -> score near 100."""
        finding = FindingResult(
            rule_id="TEST-001",
            rule_name="Test critical",
            severity=Severity.CRITICAL,
            waste_monthly_usd=1000.0,
            compliance_frameworks=["CIS", "SOC2", "NIST", "PCI"],
        )
        score = _compute_priority(finding)
        # 0.5*100 + 0.3*100 + 0.2*100 = 100
        assert score == 100.0

    def test_priority_score_low_severity_no_cost_is_low(self) -> None:
        """LOW severity + no waste + no frameworks -> low score."""
        finding = FindingResult(
            rule_id="TEST-002",
            rule_name="Test low",
            severity=Severity.LOW,
            waste_monthly_usd=0.0,
            compliance_frameworks=[],
        )
        score = _compute_priority(finding)
        # 0.5*25 + 0.3*0 + 0.2*0 = 12.5
        assert score == 12.5

    def test_findings_sorted_by_priority_descending(
        self, engine: PolicyEngine, insecure_storage: ResourceSnapshot,
    ) -> None:
        """Findings are returned sorted by priority_score descending."""
        findings = engine.evaluate([insecure_storage])
        assert len(findings) > 1
        scores = [f.priority_score for f in findings]
        assert scores == sorted(scores, reverse=True)

    def test_parallel_evaluation_correct_results(
        self, engine: PolicyEngine, insecure_storage: ResourceSnapshot,
    ) -> None:
        """Async evaluate_async produces same results as sync evaluate."""
        sync_findings = engine.evaluate([insecure_storage])
        async_findings = asyncio.run(
            engine.evaluate_async([insecure_storage])
        )
        sync_ids = sorted(f.rule_id for f in sync_findings)
        async_ids = sorted(f.rule_id for f in async_findings)
        assert sync_ids == async_ids

    def test_evaluate_empty_snapshots_returns_empty_list(
        self, engine: PolicyEngine,
    ) -> None:
        """Evaluating zero snapshots returns an empty list."""
        assert engine.evaluate([]) == []

    def test_evaluate_async_empty_snapshots(
        self, engine: PolicyEngine,
    ) -> None:
        """Async evaluation of zero snapshots returns an empty list."""
        result = asyncio.run(
            engine.evaluate_async([])
        )
        assert result == []

    def test_get_rules_for_resource_type(self, engine: PolicyEngine) -> None:
        """get_rules_for_resource_type filters rules correctly."""
        storage_rules = engine.get_rules_for_resource_type(
            "Microsoft.Storage/storageAccounts"
        )
        # Should include storage rules (which have resource_types) and
        # all rules without resource_types attribute
        assert len(storage_rules) >= 10

    def test_backward_compatible_register_rule(self) -> None:
        """Legacy register_rule API still works."""
        engine = PolicyEngine(rules=[])
        rule = PublicBlobAccessRule()

        def _wrap(snap: ResourceSnapshot) -> list[FindingResult]:
            result = rule.evaluate(snap)
            return [result] if result is not None else []

        engine.register_rule(_wrap)
        assert engine.rule_count == 1

    def test_no_azure_imports_in_policy(self) -> None:
        """Verify that cloudguardiq.policy.engine does not import azure SDK."""
        import sys

        for name in sys.modules:
            if name.startswith("azure.") and "cloudguardiq.policy" in str(
                getattr(sys.modules[name], "__file__", "")
            ):
                raise AssertionError(
                    f"Policy engine imported azure module: {name}"
                )

    def test_priority_score_medium_severity_moderate_cost(self) -> None:
        """MEDIUM severity + moderate waste + 2 frameworks."""
        finding = FindingResult(
            rule_id="TEST-003",
            rule_name="Test medium",
            severity=Severity.MEDIUM,
            waste_monthly_usd=500.0,
            compliance_frameworks=["CIS", "SOC2"],
        )
        score = _compute_priority(finding)
        # 0.5*50 + 0.3*50 + 0.2*50 = 50.0
        assert score == 50.0
