"""Tests for API authentication dependency."""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock, patch

import jwt
import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from cloudguardiq.api.auth import TokenPayload, verify_token

_TEST_SECRET = "test-secret-key-for-unit-tests-only-32b"
_TEST_TENANT = "test-tenant-id"
_TEST_CLIENT_ID = "test-client-id"

_auth_dep = Depends(verify_token)


def _make_token(
    *,
    sub: str = "user@example.com",
    aud: str = _TEST_CLIENT_ID,
    iss: str | None = None,
    exp: int | None = None,
) -> str:
    payload: dict[str, Any] = {
        "sub": sub,
        "aud": aud,
        "iss": iss or f"https://login.microsoftonline.com/{_TEST_TENANT}/v2.0",
        "exp": exp or int(time.time()) + 3600,
    }
    return jwt.encode(payload, _TEST_SECRET, algorithm="HS256")


def _build_app() -> FastAPI:
    """Minimal app with a protected route."""
    test_app = FastAPI()

    @test_app.get("/protected")
    async def protected(
        user: TokenPayload = _auth_dep,
    ) -> dict[str, str]:
        return {"sub": user.sub}

    return test_app


@pytest.fixture
async def client() -> AsyncClient:
    test_app = _build_app()
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestAuthDisabled:
    @pytest.mark.asyncio
    @patch("cloudguardiq.api.auth.get_settings")
    async def test_auth_disabled_allows_request(
        self,
        mock_settings: MagicMock,
    ) -> None:
        settings = MagicMock()
        settings.auth_disabled = True
        mock_settings.return_value = settings
        test_app = _build_app()
        transport = ASGITransport(app=test_app)
        async with AsyncClient(
            transport=transport, base_url="http://test",
        ) as ac:
            resp = await ac.get("/protected")
        assert resp.status_code == 200
        assert resp.json()["sub"] == "anonymous"


class TestAuthEnabled:
    @pytest.mark.asyncio
    async def test_missing_token_returns_403(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get("/protected")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_invalid_token_returns_401(
        self, client: AsyncClient,
    ) -> None:
        resp = await client.get(
            "/protected",
            headers={"Authorization": "Bearer not-a-jwt"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    @patch("cloudguardiq.api.auth._decode_token")
    async def test_valid_token_returns_payload(
        self, mock_decode: MagicMock, client: AsyncClient,
    ) -> None:
        mock_decode.return_value = {
            "sub": "user@example.com",
            "aud": _TEST_CLIENT_ID,
            "iss": f"https://login.microsoftonline.com/{_TEST_TENANT}/v2.0",
            "exp": int(time.time()) + 3600,
        }
        token = _make_token()
        resp = await client.get(
            "/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["sub"] == "user@example.com"

    @pytest.mark.asyncio
    @patch("cloudguardiq.api.auth._decode_token")
    async def test_expired_token_returns_401(
        self, mock_decode: MagicMock, client: AsyncClient,
    ) -> None:
        mock_decode.side_effect = jwt.ExpiredSignatureError("expired")
        token = _make_token(exp=int(time.time()) - 3600)
        resp = await client.get(
            "/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401
        assert "expired" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    @patch("cloudguardiq.api.auth._decode_token")
    async def test_wrong_audience_returns_401(
        self, mock_decode: MagicMock, client: AsyncClient,
    ) -> None:
        mock_decode.side_effect = jwt.InvalidAudienceError("bad aud")
        token = _make_token(aud="wrong-audience")
        resp = await client.get(
            "/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401


class TestDecodeToken:
    def test_decode_with_valid_key(self) -> None:
        from cloudguardiq.api.auth import _decode_token

        token = jwt.encode(
            {
                "sub": "user",
                "aud": "aud",
                "iss": f"https://login.microsoftonline.com/{_TEST_TENANT}/v2.0",
                "exp": int(time.time()) + 3600,
            },
            _TEST_SECRET,
            algorithm="HS256",
        )
        with patch("cloudguardiq.api.auth._get_signing_keys") as mock_keys:
            mock_key = MagicMock()
            mock_key.key = _TEST_SECRET
            mock_keys.return_value = [mock_key]
            result = _decode_token(token, "aud", _TEST_TENANT)
        assert result["sub"] == "user"


class TestGetSigningKeys:
    @patch("cloudguardiq.api.auth.PyJWKClient")
    def test_caches_keys_per_tenant(
        self, mock_jwk_cls: MagicMock,
    ) -> None:
        from cloudguardiq.api.auth import _get_signing_keys, _jwks_cache

        _jwks_cache.clear()
        mock_client = MagicMock()
        mock_key = MagicMock()
        mock_key.key = "some-key"
        mock_client.get_signing_keys.return_value = [mock_key]
        mock_jwk_cls.return_value = mock_client
        keys1 = _get_signing_keys("tenant-cache-test")
        keys2 = _get_signing_keys("tenant-cache-test")
        assert keys1 == keys2
        assert mock_jwk_cls.call_count == 1
        _jwks_cache.clear()


class TestOrgIdentity:
    @pytest.mark.asyncio
    @patch("cloudguardiq.api.auth.get_settings")
    async def test_auth_disabled_sets_anonymous_org_id(
        self, mock_settings: MagicMock,
    ) -> None:
        from cloudguardiq.api.auth import verify_token
        from cloudguardiq.core.identity import ANONYMOUS_ORG_ID

        settings = MagicMock()
        settings.auth_disabled = True
        mock_settings.return_value = settings
        payload = await verify_token(None)
        assert payload.org_id == ANONYMOUS_ORG_ID

    @pytest.mark.asyncio
    @patch("cloudguardiq.api.auth._decode_token")
    @patch("cloudguardiq.api.auth.get_settings")
    async def test_valid_token_derives_org_id_from_tid(
        self, mock_settings: MagicMock, mock_decode: MagicMock,
    ) -> None:
        from fastapi.security import HTTPAuthorizationCredentials

        from cloudguardiq.api.auth import verify_token

        settings = MagicMock()
        settings.auth_disabled = False
        settings.azure_client_id = _TEST_CLIENT_ID
        settings.azure_tenant_id = _TEST_TENANT
        mock_settings.return_value = settings
        mock_decode.return_value = {
            "sub": "u", "aud": _TEST_CLIENT_ID,
            "iss": "iss", "tid": _TEST_TENANT, "oid": "oid-1",
        }
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="x")
        payload = await verify_token(creds)
        assert payload.org_id == _TEST_TENANT
        assert payload.tid == _TEST_TENANT

    def test_get_org_id_returns_org_id(self) -> None:
        from cloudguardiq.api.auth import TokenPayload, get_org_id

        assert get_org_id(TokenPayload(sub="u", org_id="o-1")) == "o-1"

    def test_get_org_id_missing_raises_401(self) -> None:
        from fastapi import HTTPException

        from cloudguardiq.api.auth import TokenPayload, get_org_id

        with pytest.raises(HTTPException) as exc:
            get_org_id(TokenPayload(sub="u"))
        assert exc.value.status_code == 401

    def test_get_azure_tenant_id_returns_tid(self) -> None:
        from cloudguardiq.api.auth import TokenPayload, get_azure_tenant_id

        assert get_azure_tenant_id(TokenPayload(sub="u", tid="t-9")) == "t-9"
