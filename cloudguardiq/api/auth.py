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
    """Decode and validate a JWT token against Azure AD JWKS."""
    signing_keys = _get_signing_keys(tenant_id)

    # Accept both v1 and v2 issuer formats from Azure AD
    valid_issuers = [
        f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        f"https://sts.windows.net/{tenant_id}/",
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
        return TokenPayload(sub="anonymous")

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
    )
