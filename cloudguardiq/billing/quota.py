"""CloudGuardIQ -- Plan-tier quota helpers (cloud-agnostic).

Shared between the synchronous API path
(:mod:`cloudguardiq.api.main`) and the asynchronous Azure Functions
worker (`function_app.ai_worker_trigger`) so quota semantics are
identical regardless of how a remediation request enters the system.

There is intentionally no tight coupling to FastAPI here -- callers
get a small dataclass-style result and decide how to surface it
(HTTP 402 vs. log + drop the queue message).
"""

from __future__ import annotations

import logging
import time as _time

from pydantic import BaseModel

from cloudguardiq.billing.plans import UNLIMITED, get_plan
from cloudguardiq.billing.repository import BillingRepository
from cloudguardiq.billing.usage import UsageRepository
from cloudguardiq.core.enums import SubscriptionTier

logger = logging.getLogger(__name__)


class QuotaCheck(BaseModel):
    """Result of a plan quota check."""

    allowed: bool
    tier: SubscriptionTier
    limit: str
    cap: int
    current: int
    retry_after_seconds: int = 0

    def to_detail(self) -> dict[str, object]:
        """Return a JSON-friendly ``upgrade_required`` payload."""
        payload: dict[str, object] = {
            "error": "upgrade_required",
            "current_tier": self.tier.value.lower(),
            "limit": self.limit,
            "cap": self.cap,
            "current": self.current,
        }
        if self.retry_after_seconds > 0:
            payload["retry_after_seconds"] = self.retry_after_seconds
        return payload


async def check_ai_quota(
    tenant_id: str,
    *,
    billing_repo: BillingRepository,
    usage_repo: UsageRepository,
) -> QuotaCheck:
    """Return whether *tenant_id* may consume one more AI remediation.

    The check is best-effort: if either repository is misbehaving the
    caller should treat the tenant as allowed (defensive default), since
    a hard failure in metering must never block paying customers.
    """
    record = await billing_repo.get(tenant_id)
    tier = record.tier if record is not None else SubscriptionTier.FREE
    plan = get_plan(tier)
    cap = plan.max_ai_remediations_per_month
    usage = await usage_repo.get_current(tenant_id)
    current = usage.ai_remediations
    allowed = cap == UNLIMITED or current < cap
    return QuotaCheck(
        allowed=allowed,
        tier=tier,
        limit="ai_remediations_per_month",
        cap=cap,
        current=current,
    )


async def record_ai_remediation(
    tenant_id: str,
    *,
    usage_repo: UsageRepository,
) -> None:
    """Increment the monthly AI remediation counter for *tenant_id*.

    Failures are logged and swallowed -- metering is never allowed to
    fail an otherwise-successful generation.
    """
    try:
        await usage_repo.increment_ai_remediations(tenant_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("AI usage increment failed for %s: %s", tenant_id, exc)



async def check_scan_frequency_quota(
    tenant_id: str,
    subscription_id: str,
    *,
    billing_repo: BillingRepository,
    repo: object,
) -> QuotaCheck:
    """Return whether *tenant_id* may launch another scan for *subscription_id*.

    Each plan tier defines a minimum interval between scans
    (Free=1440 min, Starter=60 min, Enterprise=15 min). This check
    queries Cosmos for the most recent ``scan_result`` document for the
    subscription and compares its ``_ts`` (epoch seconds, set by Cosmos)
    against the plan's ``scan_frequency_minutes``.

    Best-effort: if the repository call fails or no prior scan exists the
    tenant is allowed -- metering must never block the very first scan
    or transient backend hiccups.
    """
    record = await billing_repo.get(tenant_id)
    tier = record.tier if record is not None else SubscriptionTier.FREE
    plan = get_plan(tier)
    cap_minutes = plan.scan_frequency_minutes

    last_ts: int | None = None
    if repo is not None:
        try:
            doc = await repo.get_latest_scan_for_subscription(subscription_id)  # type: ignore[attr-defined]
            if doc is not None:
                ts = doc.get("_ts")
                if isinstance(ts, (int, float)):
                    last_ts = int(ts)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Scan frequency lookup failed for %s/%s: %s",
                tenant_id, subscription_id, exc,
            )
            last_ts = None

    if last_ts is None:
        return QuotaCheck(
            allowed=True,
            tier=tier,
            limit="scan_frequency_minutes",
            cap=cap_minutes,
            current=0,
            retry_after_seconds=0,
        )

    elapsed = max(0, int(_time.time()) - last_ts)
    min_seconds = cap_minutes * 60
    allowed = elapsed >= min_seconds
    retry_after = 0 if allowed else (min_seconds - elapsed)
    return QuotaCheck(
        allowed=allowed,
        tier=tier,
        limit="scan_frequency_minutes",
        cap=cap_minutes,
        current=elapsed // 60,
        retry_after_seconds=retry_after,
    )
