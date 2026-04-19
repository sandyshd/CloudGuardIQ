"""Tests for NativeScanner."""

from __future__ import annotations

from cloudguardiq.adapters.native_scanner import NativeScanner
from cloudguardiq.adapters.rules.storage import StorageHttpsOnlyRule, StoragePublicAccessRule
from cloudguardiq.core.models import ResourceSnapshot


class TestNativeScanner:
    def test_scan_empty(self) -> None:
        scanner = NativeScanner()
        assert scanner.scan([]) == []

    def test_scan_with_rules(self, insecure_storage_snapshot: ResourceSnapshot) -> None:
        scanner = NativeScanner()
        scanner.register(StorageHttpsOnlyRule())  # type: ignore[arg-type]
        scanner.register(StoragePublicAccessRule())  # type: ignore[arg-type]
        findings = scanner.scan([insecure_storage_snapshot])
        assert len(findings) == 2

    def test_scan_ignores_unmatched_types(self, nsg_snapshot: ResourceSnapshot) -> None:
        scanner = NativeScanner()
        scanner.register(StorageHttpsOnlyRule())  # type: ignore[arg-type]
        findings = scanner.scan([nsg_snapshot])
        assert len(findings) == 0

    def test_scan_handles_rule_error(self, storage_snapshot: ResourceSnapshot) -> None:
        scanner = NativeScanner()

        class BadRule:
            rule_id = "BAD"
            resource_types = ["*"]

            def evaluate(self, snap: ResourceSnapshot) -> list:
                raise RuntimeError("fail")

        scanner.register(BadRule())  # type: ignore[arg-type]
        findings = scanner.scan([storage_snapshot])
        assert findings == []
