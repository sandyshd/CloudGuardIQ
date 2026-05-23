"""Phase 11 audit: verify multi-cloud subscription records are well-formed.

Background
----------
Until the Phase 11 ``function_app._build_scan_pipeline`` refactor, every
``SubscriptionRecord`` -- regardless of its ``provider`` field -- was
routed to ``AzureAdapter`` by the timer. AWS records mirrored by
``_mirror_aws_account_for_operator`` therefore never produced findings,
even though the Cosmos document looked correct.

After that fix, the timer dispatches by ``rec.provider``, but records
that were created in *earlier* code paths (where the provider field did
not exist or was mis-stamped) can still mis-route. This script audits
the ``subscriptions`` container, classifies each row, and either reports
the issues or marks the broken rows ``Disabled`` so the timer stops
hammering them while the owner re-onboards from the UI.

Usage::

    # Read-only audit (always start here).
    python -m scripts.audit_subscription_records

    # Disable the rows the audit flags as broken so the timer leaves
    # them alone. Re-onboarding from the Settings UI restores them.
    python -m scripts.audit_subscription_records --disable-broken

Exit codes:
    0  Audit completed -- no broken rows.
    1  Audit completed -- at least one broken row was found.
    2  Cosmos is not configured (env vars missing).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import re
import sys
from dataclasses import dataclass

from cloudguardiq.core.config import get_settings
from cloudguardiq.core.database import CosmosRepository
from cloudguardiq.subscriptions.repository import (
    SubscriptionRecord,
    SubscriptionsRepository,
)

logger = logging.getLogger("cloudguardiq.audit.subs")

_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_AWS_ACCOUNT_RE = re.compile(r"^\d{12}$")
_GCP_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


@dataclass(slots=True)
class AuditIssue:
    """Single problem found on a SubscriptionRecord."""

    tenant_id: str
    subscription_id: str
    provider: str
    reason: str


def classify(rec: SubscriptionRecord) -> list[str]:
    """Return a list of issue reasons for *rec*. Empty list = healthy."""
    issues: list[str] = []
    provider = rec.provider.value
    sub_id = rec.subscription_id.strip()

    if not sub_id:
        issues.append("subscription_id is empty")

    if provider == "AZURE":
        if not _GUID_RE.match(sub_id):
            # Heuristic: looks like an AWS account or GCP project but
            # carries provider=AZURE -> almost certainly mis-classified.
            if _AWS_ACCOUNT_RE.match(sub_id):
                issues.append("subscription_id is a 12-digit AWS account but provider=AZURE")
            elif _GCP_PROJECT_RE.match(sub_id) and "-" in sub_id:
                issues.append("subscription_id matches GCP project shape but provider=AZURE")
            else:
                issues.append("subscription_id is not a valid Azure GUID")
    elif provider == "AWS":
        if not rec.aws_account_id:
            issues.append("provider=AWS but aws_account_id is empty")
        elif not _AWS_ACCOUNT_RE.match(rec.aws_account_id):
            issues.append(f"aws_account_id '{rec.aws_account_id}' is not 12 digits")
        if not rec.aws_region:
            issues.append("provider=AWS but aws_region is empty")
        if rec.aws_account_id and rec.aws_account_id != sub_id:
            issues.append(
                f"subscription_id '{sub_id}' does not match aws_account_id '{rec.aws_account_id}'"
            )
    elif provider == "GCP":
        if not rec.gcp_project_id:
            issues.append("provider=GCP but gcp_project_id is empty")
        if rec.gcp_project_id and rec.gcp_project_id != sub_id:
            issues.append(
                f"subscription_id '{sub_id}' does not match gcp_project_id '{rec.gcp_project_id}'"
            )
    else:
        issues.append(f"unknown provider '{provider}'")

    return issues


async def _scan_all(repo: SubscriptionsRepository) -> list[SubscriptionRecord]:
    """Read every SubscriptionRecord across every tenant (cross-partition)."""
    container = repo._container()  # noqa: SLF001
    if container is None:
        return []
    records: list[SubscriptionRecord] = []
    async for item in container.query_items(query="SELECT * FROM c"):
        try:
            records.append(SubscriptionRecord.from_document(item))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Skipping malformed doc id=%s: %s", item.get("id"), exc)
    return records


async def main() -> int:
    """Entry point. Returns process exit code."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(
        description="Audit multi-cloud subscription records in Cosmos.",
    )
    parser.add_argument(
        "--disable-broken",
        action="store_true",
        help="Mark broken rows state=Disabled so the timer skips them. "
             "The owner can re-enable / re-onboard from the Settings UI.",
    )
    args = parser.parse_args()

    settings = get_settings()
    if not settings.cosmos_endpoint:
        logger.error("CLOUDGUARDIQ_COSMOS_ENDPOINT is not configured.")
        return 2

    db = CosmosRepository(settings)
    await db.connect()
    try:
        repo = SubscriptionsRepository(settings, cosmos_db=db._db)  # noqa: SLF001
        records = await _scan_all(repo)
        logger.info("Loaded %d subscription record(s)", len(records))

        by_provider: dict[str, int] = {}
        broken: list[tuple[SubscriptionRecord, list[str]]] = []
        for rec in records:
            by_provider[rec.provider.value] = by_provider.get(rec.provider.value, 0) + 1
            issues = classify(rec)
            if issues:
                broken.append((rec, issues))

        # Summary table
        logger.info("Provider breakdown:")
        for prov, count in sorted(by_provider.items()):
            logger.info("  %-9s %d", prov, count)

        if not broken:
            logger.info("All records look well-formed. Nothing to do.")
            return 0

        logger.warning("Found %d broken record(s):", len(broken))
        for rec, issues in broken:
            logger.warning(
                "  tenant=%s sub=%s provider=%s state=%s",
                rec.tenant_id, rec.subscription_id, rec.provider.value, rec.state,
            )
            for reason in issues:
                logger.warning("    - %s", reason)

        if not args.disable_broken:
            logger.info(
                "Re-run with --disable-broken to mark the above rows "
                "state=Disabled (timer will skip them). The owner can "
                "re-onboard from the Settings UI to restore.",
            )
            return 1

        disabled = 0
        for rec, _ in broken:
            if rec.state == "Disabled":
                continue
            rec.state = "Disabled"
            try:
                await repo.upsert(rec)
                disabled += 1
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Failed to disable tenant=%s sub=%s: %s",
                    rec.tenant_id, rec.subscription_id, exc,
                )
        logger.info("Disabled %d broken record(s).", disabled)
        return 1
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
