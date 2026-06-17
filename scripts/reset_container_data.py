"""Reset (empty) all CloudGuardIQ Cosmos containers without deleting them.

Deletes every document from each application container so you can test the
product from a clean slate. The database and the containers themselves are
left intact -- only their items are removed.

Usage::

    # Safety guard: you must opt in explicitly.
    $env:CLOUDGUARDIQ_CONFIRM_RESET = "yes"
    python -m scripts.reset_container_data

The script uses ``DefaultAzureCredential`` (the same auth path the app uses)
and discovers each container partition key at runtime, so it works regardless
of how a container is partitioned. It is safe to re-run; an already-empty
container simply reports zero deletions.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Any

from azure.cosmos.exceptions import CosmosResourceNotFoundError

from cloudguardiq.core.config import get_settings
from cloudguardiq.core.database import CosmosRepository

logger = logging.getLogger("cloudguardiq.reset")

_CONFIRM_ENV = "CLOUDGUARDIQ_CONFIRM_RESET"

# Concurrency tuning for bulk deletes.
_CONCURRENCY = 64  # max in-flight delete requests
_BATCH = 2000  # flush queued delete tasks every N items


def _partition_value(doc: dict[str, Any], pk_path: str) -> Any:
    """Resolve a partition-key value from *doc* given a Cosmos ``/a/b`` path."""
    value: Any = doc
    for segment in pk_path.strip("/").split("/"):
        if not isinstance(value, dict):
            return None
        value = value.get(segment)
    return value


async def _reset_container(repo: CosmosRepository, container_name: str) -> tuple[int, int]:
    """Delete every document in *container_name*.

    Returns ``(scanned, deleted)``.
    """
    assert repo._db is not None  # noqa: SLF001 -- internal one-shot script
    container = repo._db.get_container_client(container_name)  # noqa: SLF001

    props = await container.read()
    pk_paths = props.get("partitionKey", {}).get("paths", ["/id"])

    sem = asyncio.Semaphore(_CONCURRENCY)
    counters = {"deleted": 0}

    async def _delete(item_id: str, pk_arg: Any) -> None:
        async with sem:
            try:
                await container.delete_item(item=item_id, partition_key=pk_arg)
            except CosmosResourceNotFoundError:
                # Already gone (idempotent re-run / concurrent delete) -- fine.
                pass
            except Exception as exc:  # noqa: BLE001 -- one bad doc must not abort
                logger.warning(
                    "%s: delete %s failed: %s",
                    container_name, item_id, str(exc).splitlines()[0],
                )
                return
            counters["deleted"] += 1
            done = counters["deleted"]
            if done % 500 == 0:
                logger.info("%s: deleted %d so far", container_name, done)

    scanned = 0
    tasks: list[asyncio.Task[None]] = []
    async for item in container.query_items(query="SELECT * FROM c"):
        scanned += 1
        item_id = item.get("id")
        if not item_id:
            logger.warning("%s: skipping doc without id", container_name)
            continue
        pk_value = [_partition_value(item, p) for p in pk_paths]
        pk_arg: Any = pk_value[0] if len(pk_value) == 1 else pk_value
        tasks.append(asyncio.create_task(_delete(item_id, pk_arg)))
        if len(tasks) >= _BATCH:
            await asyncio.gather(*tasks)
            tasks.clear()
    if tasks:
        await asyncio.gather(*tasks)

    deleted = counters["deleted"]
    logger.info("%s: scanned=%d deleted=%d", container_name, scanned, deleted)
    return scanned, deleted


async def main() -> int:
    """Entry point. Returns process exit code."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    for noisy in ("azure", "azure.core.pipeline.policies.http_logging_policy"):
        logging.getLogger(noisy).setLevel(logging.ERROR)

    if os.environ.get(_CONFIRM_ENV, "").strip().lower() not in {"yes", "true", "1"}:
        logger.error(
            "Refusing to wipe data: set %s=yes to confirm you want to delete "
            "ALL documents from every container.",
            _CONFIRM_ENV,
        )
        return 2

    settings = get_settings()
    if not settings.cosmos_endpoint:
        logger.error("CLOUDGUARDIQ_COSMOS_ENDPOINT is not configured.")
        return 2

    containers = [
        settings.cosmos_container_findings,
        settings.cosmos_container_snapshots,
        settings.cosmos_container_remediations,
        settings.cosmos_container_system,
        settings.cosmos_container_billing,
        settings.cosmos_container_subscriptions,
        settings.cosmos_container_tenant_consents,
        settings.cosmos_container_onboarding_sessions,
        settings.cosmos_container_cloud_connections,
        settings.cosmos_container_credential_refs,
        settings.cosmos_container_audit_events,
    ]

    repo = CosmosRepository(settings)
    await repo.connect()
    total_deleted = 0
    try:
        for container in containers:
            try:
                _, deleted = await _reset_container(repo, container)
                total_deleted += deleted
            except CosmosResourceNotFoundError:
                logger.info("container %s does not exist -- skipping", container)
            except Exception as exc:  # noqa: BLE001 -- continue across containers
                logger.warning("container %s reset failed: %s", container, exc)
    finally:
        await repo.close()

    logger.info("reset complete: total documents deleted=%d", total_deleted)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
