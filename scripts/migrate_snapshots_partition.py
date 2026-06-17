"""One-shot migration: move snapshots_v2 data back into snapshots.

Cosmos cannot change a container partition key in place, so this copies every
document from ``snapshots_v2`` into ``snapshots``.

Use this when standardizing on the original container name ``snapshots`` while
keeping the newer /subscription_id-partitioned document shape.

Usage::

    python -m scripts.migrate_snapshots_partition

The script is idempotent: it upserts by document ``id`` into the destination,
so re-running it simply overwrites the same rows. It never deletes from the
source -- decommission the source container manually after verifying the
destination. Auth uses ``DefaultAzureCredential`` (the same path the app uses).
"""

from __future__ import annotations

import asyncio
import logging
import sys

from cloudguardiq.core.config import get_settings
from cloudguardiq.core.database import CosmosRepository

logger = logging.getLogger("cloudguardiq.migrate_snapshots")

_SOURCE_CONTAINER = "snapshots_v2"


async def _migrate(repo: CosmosRepository, dest_container: str) -> tuple[int, int]:
    """Copy every snapshot doc from the legacy container into *dest_container*.

    Returns ``(scanned, migrated)``.
    """
    assert repo._db is not None  # noqa: SLF001 -- internal one-shot script
    source = repo._db.get_container_client(_SOURCE_CONTAINER)  # noqa: SLF001
    dest = repo._db.get_container_client(dest_container)  # noqa: SLF001
    scanned = 0
    migrated = 0
    async for item in source.query_items(
        query="SELECT * FROM c",
        enable_cross_partition_query=True,
    ):
        scanned += 1
        if not item.get("subscription_id"):
            logger.warning(
                "Skipping snapshot %s: no subscription_id (cannot partition)",
                item.get("id", "unknown"),
            )
            continue
        # Strip Cosmos system fields so the destination assigns its own.
        doc = {k: v for k, v in item.items() if not k.startswith("_")}
        await dest.upsert_item(doc)
        migrated += 1
        if migrated % 100 == 0:
            logger.info("migrated %d snapshots so far", migrated)
    logger.info(
        "snapshots migration complete: scanned=%d migrated=%d", scanned, migrated
    )
    return scanned, migrated


async def main() -> int:
    """Entry point. Returns process exit code."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    settings = get_settings()
    if not settings.cosmos_endpoint:
        logger.error("CLOUDGUARDIQ_COSMOS_ENDPOINT is not configured.")
        return 2

    dest_container = settings.cosmos_container_snapshots
    if dest_container == _SOURCE_CONTAINER:
        logger.error(
            "Destination equals source (%r). Set CLOUDGUARDIQ_COSMOS_CONTAINER_SNAPSHOTS "
            "to the target container before migrating.",
            _SOURCE_CONTAINER,
        )
        return 2

    repo = CosmosRepository(settings)
    await repo.connect()
    try:
        await _migrate(repo, dest_container)
    finally:
        await repo.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
