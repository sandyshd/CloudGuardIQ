"""CloudGuardIQ -- structured logging context for observability.

Each FastAPI request runs inside a ``ContextVar``-scoped block populated
by the request-logging middleware. Every ``LogRecord`` emitted while the
request is in flight gains ``custom_dimensions`` (the convention App
Insights expects) carrying ``request_id``, ``tenant_id``,
``subscription_id``, ``scan_id``, and ``provider``.

This is the foundation for Phase 4.5 observability and was promoted
ahead of schedule because both the CORS bug and the silent-zero-findings
RBAC bug from earlier phases would have been triaged in seconds with
per-tenant log filters.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Any

# ---------------------------------------------------------------------
# Per-request context vars
# ---------------------------------------------------------------------
# Each is intentionally scalar (str | None) -- we are not trying to model
# arbitrary structured context here, just the dimensions we slice
# dashboards by.
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
tenant_id_var: ContextVar[str | None] = ContextVar("tenant_id", default=None)
subscription_id_var: ContextVar[str | None] = ContextVar(
    "subscription_id", default=None
)
scan_id_var: ContextVar[str | None] = ContextVar("scan_id", default=None)
provider_var: ContextVar[str | None] = ContextVar("provider", default=None)


def bind_context(
    *,
    request_id: str | None = None,
    tenant_id: str | None = None,
    subscription_id: str | None = None,
    scan_id: str | None = None,
    provider: str | None = None,
) -> None:
    """Set any subset of the request-scoped context vars.

    Only non-``None`` arguments are written so callers can incrementally
    enrich the context as more info becomes available (e.g. tenant_id is
    known after JWT verification, scan_id only after the scan starts).
    """
    if request_id is not None:
        request_id_var.set(request_id)
    if tenant_id is not None:
        tenant_id_var.set(tenant_id)
    if subscription_id is not None:
        subscription_id_var.set(subscription_id)
    if scan_id is not None:
        scan_id_var.set(scan_id)
    if provider is not None:
        provider_var.set(provider)


def current_context() -> dict[str, str]:
    """Return a snapshot of the currently-bound context values.

    Empty / ``None`` values are omitted so log records and JSON outputs
    stay compact.
    """
    pairs = {
        "request_id": request_id_var.get(),
        "tenant_id": tenant_id_var.get(),
        "subscription_id": subscription_id_var.get(),
        "scan_id": scan_id_var.get(),
        "provider": provider_var.get(),
    }
    return {k: v for k, v in pairs.items() if v}


class ContextFilter(logging.Filter):
    """Attach the request-scoped context to every ``LogRecord``.

    The values are exposed two ways so downstream sinks can pick whichever
    they prefer:

    * ``record.custom_dimensions`` -- the dict shape the Azure Monitor
      OpenCensus exporter looks for.
    * ``record.<field>`` -- direct attributes for plain-text formatters.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = current_context()
        # Direct attributes (safe defaults so format strings don't blow up
        # when called outside a request).
        for key in ("request_id", "tenant_id", "subscription_id", "scan_id", "provider"):
            if not hasattr(record, key):
                setattr(record, key, ctx.get(key, ""))
        # App Insights convention.
        existing = getattr(record, "custom_dimensions", None)
        merged: dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}
        merged.update(ctx)
        record.custom_dimensions = merged
        return True


def install_context_filter(logger: logging.Logger | None = None) -> ContextFilter:
    """Attach a ``ContextFilter`` to the given logger (root by default).

    Idempotent: re-attaches a fresh filter and removes any prior instance
    so repeated calls during test setup don't stack duplicates.
    """
    target = logger if logger is not None else logging.getLogger()
    # Strip any previously installed instance.
    target.filters = [f for f in target.filters if not isinstance(f, ContextFilter)]
    flt = ContextFilter()
    target.addFilter(flt)
    return flt
