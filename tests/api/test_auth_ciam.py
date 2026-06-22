"""Tests for CIAM (Entra External ID) token validation + provisioning."""

from __future__ import annotations

import asyncio
from typing import Any

import jwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from cloudguardiq.api import auth as auth_module
from cloudguardiq.core.config import Settings
from cloudguardiq.orgs.repository import OrgRepository

CIAM_ISS = "https://contoso.ciamlogin.com/tid-guid/v2.0"


def _ciam_settings() -> Settings:
    return Settings(
        auth_disabled=False,
        ciam_authority="https://contoso.ciamlogin.com/tid-guid",
        ciam_client_id="api-app-id",
    )


@pytest.fixture(autouse=True)
def _fresh_org_repo() -> Any:
    """Give each test an isolated in-memory org store."""
    previous = auth_module._org_repo
    auth_module.configure_auth(
        org_repository=OrgRepository(Settings(), cosmos_db=None),
    )
    yield
    auth_module._org_repo = previous


def test_is_ciam_issuer_matches_effective_and_host() -> None:
    s = _ciam_settings()
    assert auth_module._is_ciam_issuer(CIAM_ISS, s) is True
    assert auth_module._is_ciam_issuer(
        "https://other.ciamlogin.com/x/v2.0", s,
    ) is True
    assert auth_module._is_ciam_issuer(
        "https://login.microsoftonline.com/tid/v2.0", s,
    ) is False
    assert auth_module._is_ciam_issuer("", s) is False


def test_verify_ciam_token_provisions_org_id(monkeypatch: Any) -> None:
    payload = {"iss": CIAM_ISS, "sub": "user-1", "aud": "api-app-id",
               "email": "a@b.com", "oid": "oid-1"}
    monkeypatch.setattr(
        auth_module, "_decode_ciam_token", lambda _t, _s: payload,
    )
    result = asyncio.run(
        auth_module._verify_ciam_token("tok", _ciam_settings()),
    )
    assert result.sub == "user-1"
    assert result.tid == ""  # CIAM logins have no Azure tenant
    assert len(result.org_id) == 32
    int(result.org_id, 16)  # org_id is hex


def test_verify_ciam_token_is_stable_for_same_subject(
    monkeypatch: Any,
) -> None:
    payload = {"iss": CIAM_ISS, "sub": "user-1", "aud": "api-app-id"}
    monkeypatch.setattr(
        auth_module, "_decode_ciam_token", lambda _t, _s: payload,
    )
    s = _ciam_settings()
    first = asyncio.run(auth_module._verify_ciam_token("tok", s))
    second = asyncio.run(auth_module._verify_ciam_token("tok", s))
    assert first.org_id == second.org_id


def test_verify_ciam_token_503_without_org_store(monkeypatch: Any) -> None:
    auth_module.configure_auth(org_repository=None)
    monkeypatch.setattr(
        auth_module,
        "_decode_ciam_token",
        lambda _t, _s: {"iss": CIAM_ISS, "sub": "u1", "aud": "api-app-id"},
    )
    with pytest.raises(HTTPException) as exc:
        asyncio.run(auth_module._verify_ciam_token("tok", _ciam_settings()))
    assert exc.value.status_code == 503


def test_verify_token_routes_ciam_by_issuer(monkeypatch: Any) -> None:
    monkeypatch.setattr(auth_module, "get_settings", _ciam_settings)
    monkeypatch.setattr(
        auth_module,
        "_decode_ciam_token",
        lambda _t, _s: {"iss": CIAM_ISS, "sub": "u9", "aud": "api-app-id"},
    )
    token = jwt.encode({"iss": CIAM_ISS, "sub": "u9"}, "secret",
                       algorithm="HS256")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    result = asyncio.run(auth_module.verify_token(creds))
    assert result.sub == "u9"
    assert result.tid == ""
    assert len(result.org_id) == 32


def test_verify_ciam_token_invalid_raises_401(monkeypatch: Any) -> None:
    def _boom(_t: str, _s: Settings) -> dict[str, Any]:
        raise jwt.InvalidTokenError("bad")

    monkeypatch.setattr(auth_module, "_decode_ciam_token", _boom)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(auth_module._verify_ciam_token("tok", _ciam_settings()))
    assert exc.value.status_code == 401
