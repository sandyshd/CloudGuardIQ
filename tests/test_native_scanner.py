"""Tests for legacy NativeScanner imports and ScannerRule protocol."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from cloudguardiq.adapters.native_scanner import RULE_REGISTRY, NativeScanner, ScannerRule


class TestLegacyImports:
    def test_scanner_rule_protocol_importable(self) -> None:
        """ScannerRule protocol should still be importable for backward compat."""
        assert "rule_id" in getattr(ScannerRule, "__annotations__", {})

    def test_rule_registry_is_list(self) -> None:
        """RULE_REGISTRY should be a list of rule instances."""
        assert isinstance(RULE_REGISTRY, list)
        assert len(RULE_REGISTRY) > 0

    def test_native_scanner_init_requires_credential(self) -> None:
        """NativeScanner requires credential and subscription_id."""
        mock_cred = MagicMock()
        with patch("cloudguardiq.adapters.native_scanner.ResourceGraphClient"):
            scanner = NativeScanner(mock_cred, "sub-123")
        assert scanner._subscription_id == "sub-123"
