"""Tests for CIAM (Entra External ID) configuration helpers."""

from __future__ import annotations

from cloudguardiq.core.config import Settings


def test_ciam_disabled_by_default() -> None:
    s = Settings()
    assert s.auth_provider == "entra_workforce"
    assert s.ciam_enabled is False
    assert s.ciam_jwks_uri == ""
    assert s.ciam_effective_issuer == ""


def test_ciam_enabled_when_configured() -> None:
    s = Settings(
        ciam_authority="https://contoso.ciamlogin.com/tid-guid",
        ciam_client_id="api-app-id",
    )
    assert s.ciam_enabled is True
    assert s.ciam_jwks_uri == (
        "https://contoso.ciamlogin.com/tid-guid/discovery/v2.0/keys"
    )
    assert s.ciam_effective_issuer == (
        "https://contoso.ciamlogin.com/tid-guid/v2.0"
    )


def test_ciam_issuer_override() -> None:
    s = Settings(
        ciam_authority="https://contoso.ciamlogin.com/tid-guid/",
        ciam_client_id="api-app-id",
        ciam_issuer="https://custom.example.com/v2.0",
    )
    assert s.ciam_effective_issuer == "https://custom.example.com/v2.0"
    # trailing slash on authority is normalised in jwks uri
    assert s.ciam_jwks_uri == (
        "https://contoso.ciamlogin.com/tid-guid/discovery/v2.0/keys"
    )
