"""Pre-scan access verification for newly linked subscriptions.

When a tenant adds a subscription via ``POST /subscriptions`` we probe
Azure Resource Graph with the CloudGuardIQ managed identity to confirm
that *Reader* role has been granted. Without RBAC the Resource Graph
query silently returns an empty list, which previously surfaced as
"scan completed, 0 findings" with no actionable hint. This module
turns that silent failure into an explicit ``access_denied`` response.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from functools import partial

from azure.core.credentials import TokenCredential
from azure.core.exceptions import HttpResponseError
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

logger = logging.getLogger(__name__)


@dataclass
class AccessProbeResult:
    """Outcome of probing Resource Graph for a subscription."""

    ok: bool
    resource_count: int
    error: str | None = None


# Counts ALL resource types so an empty subscription with Reader still
# returns ok=True (resource_count may be 0 but the query succeeds).
_PROBE_QUERY = "Resources | summarize total = count() | project total"


async def probe_subscription_access(
    credential: TokenCredential,
    subscription_id: str,
) -> AccessProbeResult:
    """Check whether the supplied credential can read *subscription_id*.

    Returns a :class:`AccessProbeResult`:

    * ``ok=True``  when the Resource Graph query returns successfully,
      even if ``resource_count`` is 0 (empty subscription still counts
      as accessible -- the user can scan it later once they deploy
      resources).
    * ``ok=False`` when Azure rejects the call (auth/RBAC) or the
      subscription does not exist for this credential.

    Network errors and SDK exceptions are caught -- the API layer should
    surface ``error`` to the user along with a copy-pasteable ``az role
    assignment create`` hint.
    """
    client = ResourceGraphClient(credential)
    options = QueryRequestOptions(result_format="objectArray")
    request = QueryRequest(
        subscriptions=[subscription_id],
        query=_PROBE_QUERY,
        options=options,
    )

    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None, partial(client.resources, request),
        )
    except HttpResponseError as exc:
        # 403 Forbidden, 401 Unauthorized, 404 SubscriptionNotFound
        status = getattr(exc, "status_code", None)
        msg = (exc.message or str(exc)).strip()
        logger.info(
            "Access probe denied sub=%s status=%s msg=%s",
            subscription_id, status, msg[:200],
        )
        return AccessProbeResult(ok=False, resource_count=0, error=msg)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Access probe failed sub=%s: %s", subscription_id, exc,
        )
        return AccessProbeResult(ok=False, resource_count=0, error=str(exc))

    total = 0
    if isinstance(response.data, list) and response.data:
        first = response.data[0]
        if isinstance(first, dict):
            total = int(first.get("total", 0) or 0)
    return AccessProbeResult(ok=True, resource_count=total)
