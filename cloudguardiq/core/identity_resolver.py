"""CloudGuardIQ -- self-discovery of the running app's MSI principal id.

When the API container starts under an Azure-assigned managed identity,
the system-assigned principal id is not knowable at Terraform plan time
without creating a self-referential loop in the resource graph. This
module sidesteps that by reading the principal id at runtime from the
``oid`` claim of a Managed Identity access token.

Result is cached per-process: a managed identity's object id never
changes for the lifetime of the underlying resource, so re-reading on
every onboarding request would be wasteful.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from threading import Lock
from typing import Any

logger = logging.getLogger(__name__)

_cached_principal_id: str | None = None
_cache_lock = Lock()


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode the (unverified) payload section of a JWT.

    The MSI endpoint returned the token; we trust it locally for the
    purpose of reading our own ``oid`` claim. We never use this for
    authorization decisions about other principals.
    """
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("token is not a JWT")
    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def _fetch_oid_from_msi() -> str | None:
    """Acquire an ARM-scoped MSI token and return its ``oid`` claim.

    Returns ``None`` (rather than raising) on any failure -- the caller
    will fall back to a placeholder string so the API never crashes
    just because identity self-discovery is unavailable (local dev,
    networking issue, etc.).
    """
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError:
        logger.debug("azure-identity not installed; skipping MSI discovery")
        return None

    try:
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        token = credential.get_token("https://management.azure.com/.default")
    except Exception as exc:  # pragma: no cover - depends on cloud env
        logger.debug("MSI token acquisition failed: %s", exc)
        return None

    try:
        claims = _decode_jwt_payload(token.token)
    except Exception as exc:
        logger.warning("Failed to decode MSI token payload: %s", exc)
        return None

    oid = claims.get("oid")
    if isinstance(oid, str) and oid:
        return oid
    return None


def resolve_principal_id(configured: str = "") -> str:
    """Return the running app's MSI principal id.

    Resolution order:

    1. The ``configured`` argument (from settings / env var) when non-empty.
       This preserves the manual override for environments that pin the
       value out-of-band.
    2. The ``CLOUDGUARDIQ_AZURE_PRINCIPAL_ID`` env var read directly --
       defensive in case the settings object was constructed before the
       env was populated.
    3. The ``oid`` claim of an MSI access token (cached after first call).
    4. A placeholder string when none of the above succeed, so callers
       can render an obviously-broken value instead of an empty string.
    """
    global _cached_principal_id

    if configured:
        return configured

    env_value = os.getenv("CLOUDGUARDIQ_AZURE_PRINCIPAL_ID", "").strip()
    if env_value:
        return env_value

    with _cache_lock:
        if _cached_principal_id is not None:
            return _cached_principal_id
        oid = _fetch_oid_from_msi()
        _cached_principal_id = oid or ""

    return _cached_principal_id or "<principal-id-not-configured>"


def reset_cache_for_testing() -> None:
    """Test helper: clear the per-process cache between cases."""
    global _cached_principal_id
    with _cache_lock:
        _cached_principal_id = None
