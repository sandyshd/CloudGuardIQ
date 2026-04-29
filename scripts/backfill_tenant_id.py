"""Phase 1 backfill: stamp tenant_id onto existing Cosmos documents.

Run once during/after the Phase 1 deploy to populate the tenant_id field
on legacy snapshots, findings and remediation card documents.

Usage::

    export CLOUDGUARDIQ_AZURE_TENANT_ID=<your-tenant-guid>
    python -m scripts.backfill_tenant_id

The script is idempotent: documents already carrying a non-empty tenant_id
are skipped. It runs against Cosmos using ``DefaultAzureCredential`` (the
same auth path the app uses).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from cloudguardiq.core.config import get_settings
from cloudguardiq.core.database import CosmosRepository

logger = logging.getLogger("cloudguardiq.backfill")


async def _backfill_container(
    repo: CosmosRepository, container_name: str, tenant_id: str
) -> tuple[int, int]:
    """Walk *container_name* and stamp ``tenant_id`` where missing.

    Returns ``(scanned, updated)``.
    """
    assert repo._db is not None  # noqa: SLF001 — internal one-shot script
    container = repo._db.get_container_client(container_name)  # noqa: SLF001
    scanned = 0
    updated = 0
    async for item in container.query_items(
        query="SELECT * FROM c",
        enable_cross_partition_query=True,
    ):
        scanned += 1
        if item.get("tenant_id"):
            continue
        item["tenant_id"] = tenant_id
        await container.upsert_item(item)
        updated += 1
        if updated % 100 == 0:
            logger.info("%s: stamped %d so far", container_name, updated)
    logger.info(
        "%s: scanned=%d updated=%d", container_name, scanned, updated
    )
    return scanned, updated


async def main() -> int:
    """Entry point. Returns process exit code."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    tenant_id = os.environ.get("CLOUDGUARDIQ_AZURE_TENANT_ID", "").strip()
    if not tenant_id:
        logger.error(
            "CLOUDGUARDIQ_AZURE_TENANT_ID is required to run the backfill."
        )
        return 2

    settings = get_settings()
    if not settings.cosmos_endpoint:
        logger.error("CLOUDGUARDIQ_COSMOS_ENDPOINT is not configured.")
        return 2

    repo = CosmosRepository(settings)
    await repo.connect()
    try:
        for container in (
            settings.cosmos_container_findings,
            settings.cosmos_container_snapshots,
            settings.cosmos_container_remediations,
        ):
            await _backfill_container(repo, container, tenant_id)
    finally:
        await repo.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
