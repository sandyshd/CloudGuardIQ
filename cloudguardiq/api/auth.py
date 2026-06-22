"""CloudGuardIQ -- FastAPI authentication dependency (Azure AD JWT)."""

from __future__ import annotations

import logging
from typing import Any

import jwt
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from pydantic import BaseModel

from cloudguardiq.core.config import Settings, get_settings
from cloudguardiq.core.identity import (
    ANONYMOUS_ORG_ID,
    derive_org_id_from_tid,
)
from cloudguardiq.orgs.repository import OrgRecord, OrgRepository

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
    tid: str = ""  # Azure AD tenant id (Azure scan correlation only)
    oid: str = ""  # Object id (per-user audit log)
    org_id: str = ""  # Canonical cloud-neutral customer/data scope


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


def get_org_id(user: TokenPayload) -> str:
    """Return the canonical ``org_id`` (customer data scope) for *user*.

    This is the value every customer-owned repository must scope by.
    Raises HTTPException(401) when it cannot be resolved.
    """
    if user.org_id:
        return user.org_id
    if user.tid:
        # Entra workforce identities derive org_id verbatim from tid.
        return derive_org_id_from_tid(user.tid)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="org_id missing from token",
    )


def get_azure_tenant_id(user: TokenPayload) -> str:
    """Return the Azure Entra ``tid`` for cross-tenant scan correlation.

    Unlike :func:`get_org_id`, this is NOT a customer data scope; it is
    used only to authenticate against the customer Azure tenant when
    scanning their subscriptions. Empty for non-Azure (CIAM) logins.
    """
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


# Org identity store (Phase 2) -- resolves a stable org_id for CIAM logins.
# Wired from the FastAPI startup hook via configure_auth(); unset by default
# so Azure workforce auth is unaffected.
_org_repo: OrgRepository | None = None


def configure_auth(*, org_repository: OrgRepository | None) -> None:
    """Wire the org identity store used to resolve CIAM ``org_id``.

    Called from the application startup hook. When unset, CIAM tokens
    cannot be provisioned and yield ``503``; Azure workforce tokens are
    unaffected.
    """
    global _org_repo  # noqa: PLW0603
    _org_repo = org_repository


def _get_ciam_signing_keys(jwks_uri: str) -> list[Any]:
    """Fetch and cache CIAM (Entra External ID) JWKS signing keys."""
    cache_key = f"ciam::{jwks_uri}"
    if cache_key not in _jwks_cache:
        client = PyJWKClient(jwks_uri)
        _jwks_cache[cache_key] = client.get_signing_keys()
    return _jwks_cache[cache_key]


def _is_ciam_issuer(iss: str, settings: Settings) -> bool:
    """Return ``True`` when *iss* identifies a CIAM (External ID) token."""
    if not iss:
        return False
    if (
        settings.ciam_effective_issuer
        and iss == settings.ciam_effective_issuer
    ):
        return True
    return "ciamlogin.com" in iss


def _decode_ciam_token(token: str, settings: Settings) -> dict[str, Any]:
    """Decode and validate a CIAM JWT against the External ID JWKS.

    Validates signature, audience (``ciam_client_id``) and issuer
    (``ciam_effective_issuer``). Raises a :mod:`jwt` error on failure.
    """
    signing_keys = _get_ciam_signing_keys(settings.ciam_jwks_uri)
    issuer = settings.ciam_effective_issuer
    audience = settings.ciam_client_id
    last_error: Exception | None = None
    for key in signing_keys:
        try:
            decoded: dict[str, Any] = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                audience=audience,
                issuer=issuer,
            )
            return decoded
        except jwt.InvalidSignatureError:
            continue
        except jwt.InvalidTokenError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise jwt.InvalidTokenError("No valid CIAM signing key found")


async def _provision_org_from_ciam(payload: dict[str, Any]) -> OrgRecord:
    """Resolve (creating if new) the org record for a CIAM identity."""
    if _org_repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Org identity store not configured",
        )
    email = str(
        payload.get("email") or payload.get("preferred_username") or "",
    )
    return await _org_repo.provision(
        issuer=str(payload.get("iss", "")),
        subject=str(payload.get("sub", "")),
        email=email,
    )


async def _verify_ciam_token(token: str, settings: Settings) -> TokenPayload:
    """Validate a CIAM token and resolve its canonical ``org_id``.

    CIAM logins have no customer Azure tenant, so ``tid`` is left empty
    and the data scope comes solely from the provisioned ``org_id``.
    """
    try:
        payload = _decode_ciam_token(token, settings)
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
    except Exception as exc:  # noqa: BLE001
        logger.warning("CIAM token verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token verification failed",
        ) from None

    org = await _provision_org_from_ciam(payload)
    return TokenPayload(
        sub=str(payload.get("sub", "")),
        aud=str(payload.get("aud", "")),
        iss=str(payload.get("iss", "")),
        tid="",
        oid=str(payload.get("oid", "")),
        org_id=org.org_id,
    )


async def verify_token(
    credentials: HTTPAuthorizationCredentials | None = _bearer_dep,
) -> TokenPayload:
    """FastAPI dependency that validates an Azure AD Bearer token.

    When ``auth_disabled`` is *True* in settings, returns an anonymous
    payload so that development and testing can proceed without Azure AD.
    """
    settings = get_settings()

    if settings.auth_disabled:
        return TokenPayload(
            sub="anonymous", tid="anonymous", org_id=ANONYMOUS_ORG_ID,
        )

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authenticated",
        )

    token = credentials.credentials

    if settings.ciam_enabled:
        unverified: dict[str, Any] = {}
        try:
            unverified = jwt.decode(
                token, options={"verify_signature": False},
            )
        except jwt.InvalidTokenError:
            unverified = {}
        if _is_ciam_issuer(
            str(unverified.get("iss") or "").strip(), settings,
        ):
            return await _verify_ciam_token(token, settings)

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

    tid = payload.get("tid", "")
    return TokenPayload(
        sub=payload.get("sub", ""),
        aud=payload.get("aud", ""),
        iss=payload.get("iss", ""),
        tid=tid,
        oid=payload.get("oid", ""),
        org_id=derive_org_id_from_tid(tid),
    )
