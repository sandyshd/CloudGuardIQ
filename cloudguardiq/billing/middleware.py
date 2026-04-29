"""CloudGuardIQ -- Tier enforcement middleware.

Free tier users are capped at:
  * ``free_max_subscriptions`` connected subscriptions
  * ``free_max_resources_per_scan`` resources scanned per scan

The middleware consults a 1-hour in-memory cache of tenant -> tier and returns
HTTP 402 with a structured payload when a limit is exceeded. It is intentionally
scoped to a handful of routes; all other traffic is passed through.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from cloudguardiq.billing.repository import BillingRepository
from cloudguardiq.core.config import Settings
from cloudguardiq.core.enums import SubscriptionTier

logger = logging.getLogger(__name__)

# Routes that enforce tier limits. Each entry is (method, path_prefix, limit_kind).
_ENFORCED_ROUTES: list[tuple[str, str, str]] = [
    ("POST", "/scan", "resources_per_scan"),
    # NOTE: POST /subscriptions tier cap is enforced inside the route
    # handler (cloudguardiq.api.subscriptions) using the JWT tid claim,
    # which is more reliable than the middleware's anonymous tenant lookup.
]

# Routes that must never be blocked (webhook, health, docs, billing).
_BYPASS_PREFIXES = (
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/billing",
)

_CACHE_TTL_SECONDS = 3600

_CallNext = Callable[[Request], Awaitable[Response]]


def _anonymous_tenant(request: Request) -> str:
    """Return a stable id for the calling tenant.

    Uses ``X-Tenant-Id`` header if present, otherwise the client host. This is
    a best-effort fallback used while the full Azure AD claim mapping is wired
    through ``verify_token``.
    """
    header = request.headers.get("x-tenant-id")
    if header:
        return header
    if request.client is not None:
        return request.client.host
    return "anonymous"


class TierEnforcementMiddleware(BaseHTTPMiddleware):
    """Deny requests that exceed the caller's subscription tier limits."""

    def __init__(
        self,
        app: Callable[..., Awaitable[Response]],
        *,
        settings: Settings,
        repository: BillingRepository,
        subscription_counter: Callable[[str], Awaitable[int]] | None = None,
    ) -> None:
        """Create the middleware.

        *subscription_counter* returns the current count of connected
        subscriptions for a tenant; if omitted, the subscription check is
        skipped.
        """
        super().__init__(app)
        self._settings = settings
        self._repo = repository
        self._subscription_counter = subscription_counter
        self._cache: dict[str, tuple[SubscriptionTier, float]] = {}

    async def _resolve_tier(self, tenant_id: str) -> SubscriptionTier:
        """Return the cached tier for *tenant_id*, refreshing if stale."""
        cached = self._cache.get(tenant_id)
        now = time.monotonic()
        if cached is not None and now - cached[1] < _CACHE_TTL_SECONDS:
            return cached[0]
        record = await self._repo.get(tenant_id)
        tier = record.tier if record else SubscriptionTier.FREE
        self._cache[tenant_id] = (tier, now)
        return tier

    def invalidate(self, tenant_id: str) -> None:
        """Drop the cached tier for *tenant_id* (called from webhook handler)."""
        self._cache.pop(tenant_id, None)

    def _match_rule(
        self, method: str, path: str,
    ) -> str | None:
        """Return the limit kind for the request, or ``None`` to pass through."""
        for m, prefix, kind in _ENFORCED_ROUTES:
            if method == m and path.startswith(prefix):
                return kind
        return None

    async def _over_scan_limit(self, request: Request) -> bool:
        """Return True if the scan request exceeds the per-scan resource cap."""
        declared = request.headers.get("x-expected-resource-count")
        if declared is None:
            return False
        try:
            count = int(declared)
        except ValueError:
            return False
        return count > self._settings.free_max_resources_per_scan

    async def _over_subscription_limit(self, tenant_id: str) -> bool:
        """Return True if the tenant already has too many subscriptions."""
        if self._subscription_counter is None:
            return False
        try:
            current = await self._subscription_counter(tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Subscription counter failed: %s", exc)
            return False
        return current >= self._settings.free_max_subscriptions

    async def dispatch(  # type: ignore[override]
        self,
        request: Request,
        call_next: _CallNext,
    ) -> Response:
        """Gate the request based on the caller's subscription tier."""
        path = request.url.path
        if any(path.startswith(p) for p in _BYPASS_PREFIXES):
            return await call_next(request)

        kind = self._match_rule(request.method, path)
        if kind is None:
            return await call_next(request)

        tenant_id = _anonymous_tenant(request)
        tier = await self._resolve_tier(tenant_id)
        if tier != SubscriptionTier.FREE:
            return await call_next(request)

        exceeded = False
        limit_name = ""
        if kind == "resources_per_scan":
            exceeded = await self._over_scan_limit(request)
            limit_name = "resources_per_scan"
        elif kind == "subscriptions":
            exceeded = await self._over_subscription_limit(tenant_id)
            limit_name = "subscriptions"

        if exceeded:
            logger.info(
                "Tier enforcement blocked %s %s for tenant=%s (limit=%s)",
                request.method, path, tenant_id, limit_name,
            )
            return JSONResponse(
                status_code=402,
                content={
                    "error": "upgrade_required",
                    "current_tier": tier.value.lower(),
                    "limit": limit_name,
                },
            )

        return await call_next(request)
