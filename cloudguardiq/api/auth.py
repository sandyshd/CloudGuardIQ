"""CloudGuardIQ -- FastAPI authentication dependency (Azure AD JWT)."""

from __future__ import annotations

import logging
from typing import Any

import jwt
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from pydantic import BaseModel

from cloudguardiq.core.config import get_settings

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)
_bearer_dep = Security(_bearer)

# Cache JWKS keys per tenant to avoid repeated HTTP calls.
_jwks_cache: dict[str, list[Any]] = {}


class TokenPayload(BaseModel):
    """Decoded JWT token payload."""

    sub: str
    aud: str = ""
    iss: str = ""
    tid: str = ""  # Azure AD tenant id (multi-tenant scoping)
    oid: str = ""  # Object id (per-user audit log)


def get_tenant_id(user: TokenPayload) -> str:
    """Return the validated tenant id from a token payload.

    Raises HTTPException(401) when ``tid`` is missing. ``oid`` is optional
    and used only for audit logging.
    """
    if not user.tid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tenant id (tid) missing from token",
        )
    return user.tid


def _get_signing_keys(tenant_id: str) -> list[Any]:
    """Fetch and cache Azure AD JWKS signing keys for *tenant_id*."""
    if tenant_id not in _jwks_cache:
        jwks_url = (
            f"https://login.microsoftonline.com/{tenant_id}"
            "/discovery/v2.0/keys"
        )
        client = PyJWKClient(jwks_url)
        _jwks_cache[tenant_id] = client.get_signing_keys()
    return _jwks_cache[tenant_id]


def _decode_token(
    token: str,
    audience: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Decode and validate a JWT token against Azure AD JWKS.

    Multi-tenant aware (Phase 3.1): when the unverified ``tid`` claim
    points at a tenant other than the configured home tenant, the
    function fetches signing keys for that tenant and validates the
    issuer against ``login.microsoftonline.com/{tid}``. The caller is
    responsible for then enforcing whatever consent / allowlist policy
    applies (typically by checking
    :class:`TenantConsentRepository`).
    """
    try:
        unverified = jwt.decode(
            token, options={"verify_signature": False},
        )
    except jwt.InvalidTokenError as exc:
        raise jwt.InvalidTokenError(f"Token not parseable: {exc}") from None
    token_tid = str(unverified.get("tid") or "").strip()

    candidate_tids: list[str] = []
    if tenant_id:
        candidate_tids.append(tenant_id)
    if token_tid and token_tid not in candidate_tids:
        candidate_tids.append(token_tid)
    if not candidate_tids:
        raise jwt.InvalidTokenError("Token missing tid and no home tenant")

    last_error: Exception | None = None
    for tid in candidate_tids:
        try:
            signing_keys = _get_signing_keys(tid)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue

        valid_issuers = [
            f"https://login.microsoftonline.com/{tid}/v2.0",
            f"https://sts.windows.net/{tid}/",
        ]

        for key in signing_keys:
            for issuer in valid_issuers:
                try:
                    decoded: dict[str, Any] = jwt.decode(
                        token,
                        key.key,
                        algorithms=["RS256", "HS256"],
                        audience=audience,
                        issuer=issuer,
                    )
                    return decoded
                except jwt.InvalidIssuerError:
                    continue
                except jwt.InvalidSignatureError:
                    break
                except jwt.InvalidTokenError as exc:
                    last_error = exc

    if last_error is not None:
        raise jwt.InvalidTokenError(str(last_error))
    raise jwt.InvalidTokenError("No valid signing key found")


async def verify_token(
    credentials: HTTPAuthorizationCredentials | None = _bearer_dep,
) -> TokenPayload:
    """FastAPI dependency that validates an Azure AD Bearer token.

    When ``auth_disabled`` is *True* in settings, returns an anonymous
    payload so that development and testing can proceed without Azure AD.
    """
    settings = get_settings()

    if settings.auth_disabled:
        return TokenPayload(sub="anonymous", tid="anonymous")

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authenticated",
        )

    token = credentials.credentials

    try:
        payload = _decode_token(
            token,
            audience=settings.azure_client_id,
            tenant_id=settings.azure_tenant_id,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        ) from None
    except (jwt.InvalidAudienceError, jwt.InvalidIssuerError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token claims: {exc}",
        ) from None
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from None
    except Exception as exc:
        logger.warning("Token verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token verification failed",
        ) from None

    return TokenPayload(
        sub=payload.get("sub", ""),
        aud=payload.get("aud", ""),
        iss=payload.get("iss", ""),
        tid=payload.get("tid", ""),
        oid=payload.get("oid", ""),
    )
