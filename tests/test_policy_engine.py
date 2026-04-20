"""Tests for PolicyEngine (legacy backward-compatible tests)."""

from __future__ import annotations

from cloudguardiq.adapters.rules.storage import StorageHttpsOnlyRule, StoragePublicAccessRule
from cloudguardiq.core.enums import Severity
from cloudguardiq.core.models import ResourceSnapshot
from cloudguardiq.policy.engine import PolicyEngine


class TestPolicyEngine:
    def test_evaluate_with_no_rules(self, storage_snapshot: ResourceSnapshot) -> None:
        engine = PolicyEngine(rules=[])
        findings = engine.evaluate([storage_snapshot])
        assert findings == []

    def test_evaluate_with_rules(self, insecure_storage_snapshot: ResourceSnapshot) -> None:
        engine = PolicyEngine(rules=[])
        engine.register_rule(StorageHttpsOnlyRule().evaluate)
        engine.register_rule(StoragePublicAccessRule().evaluate)
        findings = engine.evaluate([insecure_storage_snapshot])
        assert len(findings) == 2

    def test_rule_count(self) -> None:
        engine = PolicyEngine(rules=[])
        assert engine.rule_count == 0
        engine.register_rule(StorageHttpsOnlyRule().evaluate)
        assert engine.rule_count == 1

    def test_severity_filter(self, insecure_storage_snapshot: ResourceSnapshot) -> None:
        engine = PolicyEngine(rules=[])
        engine.register_rule(StorageHttpsOnlyRule().evaluate)
        engine.register_rule(StoragePublicAccessRule().evaluate)
        engine.set_severity_filter(Severity.CRITICAL)
        findings = engine.evaluate([insecure_storage_snapshot])
        assert all(f.severity == Severity.CRITICAL for f in findings)

    def test_failing_rule_handled(self, storage_snapshot: ResourceSnapshot) -> None:
        engine = PolicyEngine(rules=[])

        def bad_rule(snap: ResourceSnapshot) -> list:
            raise ValueError("boom")

        engine.register_rule(bad_rule)
        findings = engine.evaluate([storage_snapshot])
        assert findings == []

    def test_no_azure_imports_in_policy(self) -> None:
        """Verify that cloudguardiq.policy.engine does not import azure SDK."""
        import sys

        for name in sys.modules:
            if name.startswith("azure.") and "cloudguardiq.policy" in str(
                getattr(sys.modules[name], "__file__", "")
            ):
                raise AssertionError(f"Policy engine imported azure module: {name}")
