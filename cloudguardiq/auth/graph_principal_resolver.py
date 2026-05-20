"""CloudGuardIQ -- Resolve customer-tenant SP object id via Microsoft Graph.

When a customer in a different Entra tenant admin-consents the
CloudGuardIQ multi-tenant app, Azure auto-provisions a service
principal in their tenant. The object id of that *customer-tenant* SP
is what role assignments (e.g. Reader on a subscription) must target.

This resolver looks the SP up by ``appId`` using Microsoft Graph
(``GET /servicePrincipals(appId='<client-id>')``) so the onboarding
wizard can show the correct principal id per customer rather than the
home-tenant SP id (which is wrong in any other directory).

Failures fall into two categories so callers can react appropriately:

* :class:`PrincipalNotFoundError` -- the SP doesn't exist in the
  customer tenant. The most common cause is that an Entra ID Global
  Administrator has not yet accepted the consent URL. Callers should
  surface the consent URL.
* :class:`PrincipalLookupError` -- anything else (token failure,
  transient Graph 5xx, malformed response). Callers may retry or fall
  back to a home-tenant default.

Results are cached in-process per ``(client_id, tenant_id)`` for one
hour to avoid hammering Graph on every wizard load.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Protocol

import httpx

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_CACHE_TTL_SECONDS = 3600
_HTTP_TIMEOUT_SECONDS = 10.0


class PrincipalLookupError(Exception):
    """Raised when the Graph lookup fails for a recoverable reason."""


class PrincipalNotFoundError(PrincipalLookupError):
    """The CloudGuardIQ SP does not exist in the target customer tenant.

    Typically means an Entra ID Global Administrator has not yet
    accepted the multi-tenant admin-consent URL.
    """


class _CredentialFactoryProto(Protocol):
    def for_tenant(self, tenant_id: str) -> Any: ...


# (client_id, tenant_id) -> (expires_at_monotonic, sp_object_id)
_cache: dict[tuple[str, str], tuple[float, str]] = {}


def clear_cache() -> None:
    """Drop all cached lookups (test hook + manual invalidation)."""
    _cache.clear()


async def resolve_customer_principal_id(
    factory: _CredentialFactoryProto,
    *,
    client_id: str,
    tenant_id: str,
    http_client: httpx.AsyncClient | None = None,
) -> str:
    """Return the object id of the CloudGuardIQ SP in *tenant_id*.

    :param factory: A :class:`CustomerCredentialFactory` that yields a
        ``TokenCredential`` bound to the customer tenant.
    :param client_id: The CloudGuardIQ multi-tenant app's ``appId``.
    :param tenant_id: The customer's Entra tenant id (GUID).
    :param http_client: Optional preconfigured ``httpx.AsyncClient``;
        primarily a test seam.
    :raises PrincipalNotFoundError: SP not present in the tenant
        (admin consent likely missing).
    :raises PrincipalLookupError: any other failure.
    """
    if not client_id:
        raise PrincipalLookupError("client_id is required")
    if not tenant_id:
        raise PrincipalLookupError("tenant_id is required")

    key = (client_id, tenant_id.lower())
    now = time.monotonic()
    cached = _cache.get(key)
    if cached and cached[0] > now:
        return cached[1]

    try:
        credential = factory.for_tenant(tenant_id)
    except Exception as exc:  # noqa: BLE001
        raise PrincipalLookupError(
            f"credential factory failed for tenant {tenant_id}: {exc}",
        ) from exc

    try:
        token = await asyncio.to_thread(credential.get_token, GRAPH_SCOPE)
    except Exception as exc:  # noqa: BLE001
        raise PrincipalLookupError(
            f"failed to acquire Graph token for tenant {tenant_id}: {exc}",
        ) from exc

    url = f"{GRAPH_BASE}/servicePrincipals(appId='{client_id}')?$select=id"
    headers = {
        "Authorization": f"Bearer {token.token}",
        "Accept": "application/json",
    }

    async def _do(client: httpx.AsyncClient) -> httpx.Response:
        return await client.get(url, headers=headers, timeout=_HTTP_TIMEOUT_SECONDS)

    if http_client is None:
        async with httpx.AsyncClient() as client:
            resp = await _do(client)
    else:
        resp = await _do(http_client)

    if resp.status_code == 404:
        raise PrincipalNotFoundError(
            f"Service principal for appId={client_id} not found in tenant "
            f"{tenant_id}; admin consent has likely not been granted.",
        )
    if resp.status_code >= 400:
        raise PrincipalLookupError(
            f"Graph returned {resp.status_code}: {resp.text[:200]}",
        )

    try:
        data = resp.json()
        oid = data["id"]
    except (KeyError, ValueError) as exc:
        raise PrincipalLookupError(
            f"unexpected Graph response: {exc}",
        ) from exc

    if not isinstance(oid, str) or not oid:
        raise PrincipalLookupError("Graph returned an empty object id")

    _cache[key] = (now + _CACHE_TTL_SECONDS, oid)
    logger.info(
        "Resolved CloudGuardIQ SP id %s for tenant %s via Graph",
        oid, tenant_id,
    )
    return oid
