"""Tests for runtime MSI principal id self-discovery."""

from __future__ import annotations

import base64
import json
from typing import Any
from unittest.mock import patch

from cloudguardiq.core import identity_resolver


def _make_jwt(claims: dict[str, Any]) -> str:
    """Build a JWT-shaped string with the given claims (no signature needed)."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.signature"


def test_resolve_prefers_configured_value() -> None:
    identity_resolver.reset_cache_for_testing()
    assert identity_resolver.resolve_principal_id("explicit-oid") == "explicit-oid"


def test_resolve_uses_env_when_no_configured_value(monkeypatch) -> None:
    identity_resolver.reset_cache_for_testing()
    monkeypatch.setenv("CLOUDGUARDIQ_AZURE_PRINCIPAL_ID", "env-oid")
    assert identity_resolver.resolve_principal_id("") == "env-oid"


def test_resolve_falls_back_to_msi_token_oid(monkeypatch) -> None:
    identity_resolver.reset_cache_for_testing()
    monkeypatch.delenv("CLOUDGUARDIQ_AZURE_PRINCIPAL_ID", raising=False)
    token = _make_jwt({"oid": "msi-discovered-oid", "appid": "x"})
    with patch.object(identity_resolver, "_fetch_oid_from_msi", return_value="msi-discovered-oid") as m:
        result = identity_resolver.resolve_principal_id("")
    assert result == "msi-discovered-oid"
    assert m.call_count == 1


def test_resolve_caches_msi_lookup(monkeypatch) -> None:
    identity_resolver.reset_cache_for_testing()
    monkeypatch.delenv("CLOUDGUARDIQ_AZURE_PRINCIPAL_ID", raising=False)
    with patch.object(identity_resolver, "_fetch_oid_from_msi", return_value="cached-oid") as m:
        first = identity_resolver.resolve_principal_id("")
        second = identity_resolver.resolve_principal_id("")
    assert first == second == "cached-oid"
    # MSI is only consulted once even on repeated calls.
    assert m.call_count == 1


def test_resolve_returns_placeholder_when_msi_unavailable(monkeypatch) -> None:
    identity_resolver.reset_cache_for_testing()
    monkeypatch.delenv("CLOUDGUARDIQ_AZURE_PRINCIPAL_ID", raising=False)
    with patch.object(identity_resolver, "_fetch_oid_from_msi", return_value=None):
        result = identity_resolver.resolve_principal_id("")
    assert result == "<principal-id-not-configured>"


def test_decode_jwt_payload_extracts_claims() -> None:
    token = _make_jwt({"oid": "abc", "tid": "def"})
    payload = identity_resolver._decode_jwt_payload(token)
    assert payload["oid"] == "abc"
    assert payload["tid"] == "def"


def test_decode_jwt_payload_rejects_non_jwt() -> None:
    import pytest
    with pytest.raises(ValueError):
        identity_resolver._decode_jwt_payload("not-a-jwt")
