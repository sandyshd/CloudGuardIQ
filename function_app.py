"""CloudGuardIQ -- Azure Functions v4 entry point."""

from __future__ import annotations

import logging
import os

import azure.functions as func

logger = logging.getLogger(__name__)

app = func.FunctionApp()


async def _build_scan_pipeline(
    subscription_id: str,
    db,
    async_credential,
    *,
    customer_tenant_id: str = "",
    provider: str = "AZURE",
    aws_account_id: str = "",
    aws_region: str = "us-east-1",
    gcp_project_id: str = "",
):
    """Build a ScanPipeline bound to a single Azure subscription.

    The pipeline is wired with billing + usage repositories so the producer
    side of the Service Bus path respects per-tenant AI quotas (Phase 2.6):
    a capped tenant's lowest-priority findings are not queued at all
    instead of being queued and then dropped by the consumer worker.

    For Phase 3 cross-tenant scans, when *customer_tenant_id* is
    supplied and a customer credential factory is configured, the
    synchronous credential targets the customer's Entra tenant.
    Failure to build a per-tenant credential falls back to
    DefaultAzureCredential (single-tenant path).
    """
    from azure.servicebus.aio import ServiceBusClient

    from cloudguardiq.adapters.factory import build_scan_adapter
    from cloudguardiq.billing.repository import BillingRepository
    from cloudguardiq.billing.usage import UsageRepository
    from cloudguardiq.core.config import get_settings
    from cloudguardiq.core.enums import CloudProvider
    from cloudguardiq.pipeline.scan_pipeline import ScanPipeline
    from cloudguardiq.policy.engine import PolicyEngine

    provider_upper = (provider or "AZURE").upper()
    if provider_upper == "AZURE":
        from azure.identity import (
            DefaultAzureCredential as SyncDefaultAzureCredential,
        )

        from cloudguardiq.auth.customer_credential import build_default_factory

        sync_credential = None
        if customer_tenant_id:
            factory = build_default_factory(get_settings())
            if factory is not None:
                try:
                    sync_credential = factory.for_tenant(customer_tenant_id)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Customer credential build failed tenant=%s: %s",
                        customer_tenant_id, exc,
                    )
        if sync_credential is None:
            sync_credential = SyncDefaultAzureCredential()

        adapter = build_scan_adapter(
            CloudProvider.AZURE,
            credential=sync_credential,
            subscription_id=subscription_id,
            db=db,
            async_credential=async_credential,
        )
    elif provider_upper == "AWS":
        if not aws_account_id:
            raise RuntimeError(
                f"AWS pipeline build for sub={subscription_id} "
                "missing aws_account_id"
            )
        adapter = build_scan_adapter(
            CloudProvider.AWS,
            account_id=aws_account_id,
            region=aws_region or "us-east-1",
        )
    elif provider_upper == "GCP":
        if not gcp_project_id:
            raise RuntimeError(
                f"GCP pipeline build for sub={subscription_id} "
                "missing gcp_project_id"
            )
        adapter = build_scan_adapter(
            CloudProvider.GCP,
            project_id=gcp_project_id,
        )
    else:
        raise RuntimeError(f"Unsupported provider for scan pipeline: {provider}")

    sender = None
    sb_fqns = os.environ.get("SERVICE_BUS_CONNECTION__fullyQualifiedNamespace")  # noqa: SIM112
    if sb_fqns:
        sb_client = ServiceBusClient(
            fully_qualified_namespace=sb_fqns,
            credential=async_credential,
        )
        sender = sb_client.get_queue_sender(queue_name="findings-queue")

    settings = get_settings()
    cosmos_db = db._db if db is not None else None
    billing_repo = BillingRepository(settings, cosmos_db=cosmos_db)
    usage_repo = UsageRepository(settings, cosmos_db=cosmos_db)

    return ScanPipeline(
        adapter=adapter,
        policy_engine=PolicyEngine(),
        ai_engine=None,
        db=db,
        service_bus_sender=sender,
        billing_repo=billing_repo,
        usage_repo=usage_repo,
    )


async def _list_enabled_subscriptions(db):
    """Return enabled ``SubscriptionRecord`` instances for the timer scan.

    Falls back to an empty list when the subscriptions container cannot be
    queried (e.g. cosmos misconfigured), which causes the timer to no-op
    instead of raising. Records carry ``last_scan_at`` so the trigger can
    skip tenants whose plan scan-frequency hasn't elapsed yet.
    """
    from cloudguardiq.core.config import get_settings
    from cloudguardiq.subscriptions.repository import (
        SubscriptionRecord,
        SubscriptionsRepository,
    )

    settings = get_settings()
    repo = SubscriptionsRepository(
        settings, cosmos_db=db._db if db is not None else None,
    )
    container = repo._container()  # noqa: SLF001
    if container is None:
        logger.warning("Subscriptions container unavailable; timer scan no-op")
        return [], repo

    records: list[SubscriptionRecord] = []
    try:
        async for item in container.query_items(
            query="SELECT * FROM c WHERE c.state = \u0027Enabled\u0027",
        ):
            try:
                records.append(SubscriptionRecord.from_document(item))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping malformed subscription doc: %s", exc)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to query subscriptions: %s", exc)
    return records, repo


async def _get_ai_worker():
    """Build an AIWorker from environment configuration."""
    import openai
    from azure.identity.aio import DefaultAzureCredential, get_bearer_token_provider

    from cloudguardiq.ai.remediation_engine import RemediationEngine
    from cloudguardiq.billing.repository import BillingRepository
    from cloudguardiq.billing.usage import UsageRepository
    from cloudguardiq.core.config import get_settings
    from cloudguardiq.core.database import CosmosRepository
    from cloudguardiq.pipeline.ai_worker import AIWorker

    settings = get_settings()
    db = CosmosRepository(settings)
    await db.connect()

    credential = DefaultAzureCredential()
    token_provider = get_bearer_token_provider(
        credential, "https://cognitiveservices.azure.com/.default"
    )

    openai_client = openai.AsyncAzureOpenAI(
        azure_endpoint=os.environ.get("AZURE_OPENAI_ENDPOINT", ""),
        azure_ad_token_provider=token_provider,
        api_version="2024-02-15-preview",
    )
    ai_engine = RemediationEngine(
        client=openai_client,
        deployment=os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-5.1"),
        db=db,
    )

    cosmos_db = db._db if db is not None else None
    billing_repo = BillingRepository(settings, cosmos_db=cosmos_db)
    usage_repo = UsageRepository(settings, cosmos_db=cosmos_db)

    return (
        AIWorker(
            ai_engine=ai_engine,
            db=db,
            billing_repo=billing_repo,
            usage_repo=usage_repo,
        ),
        db,
        credential,
    )


@app.timer_trigger(
    # Fire every 5 minutes. Per-tenant cooldown gating in
    # scan_trigger() enforces the actual cadence per billing plan:
    # Free = 1440 min, Starter = 60 min, Enterprise = 15 min.
    schedule="0 */5 * * * *",
    arg_name="timer",
    run_on_startup=False,
)
async def scan_trigger(timer: func.TimerRequest) -> None:
    """Timer-triggered scan that fans out across every registered subscription.

    Phase 2.5: honors per-tenant plan tier limits. For every Enabled
    ``(tenant_id, subscription_id)`` pair we:

    * Look up the tenant's plan and skip the run if the last scan was
      within ``plan.scan_frequency_minutes`` -- this enforces the
      hourly / 15-min / daily tier knobs without requiring a per-tier
      separate timer schedule.
    * Run the scan pipeline.
    * Stamp ``last_scan_at`` on success so the next tick honors the
      cooldown window.

    Failures on one subscription do not affect the others.
    """
    from datetime import datetime, timedelta, timezone

    from azure.identity.aio import DefaultAzureCredential as AsyncDefaultAzureCredential

    from cloudguardiq.billing.plans import get_plan
    from cloudguardiq.billing.repository import BillingRepository
    from cloudguardiq.core.config import get_settings
    from cloudguardiq.core.database import CosmosRepository
    from cloudguardiq.core.enums import SubscriptionTier

    settings = get_settings()
    async_credential = AsyncDefaultAzureCredential()
    db = CosmosRepository(settings)
    await db.connect()

    try:
        records, subs_repo = await _list_enabled_subscriptions(db)
        if not records:
            logger.info("No enabled subscriptions registered; timer scan no-op")
            return

        billing_repo = BillingRepository(
            settings, cosmos_db=db._db if db is not None else None,
        )

        now = datetime.now(timezone.utc)
        skipped = 0
        scanned = 0
        logger.info("Timer scan considering %d subscription(s)", len(records))
        for rec in records:
            tenant_id = rec.tenant_id
            subscription_id = rec.subscription_id

            # Plan-driven cooldown check
            billing = await billing_repo.get(tenant_id)
            tier = billing.tier if billing is not None else SubscriptionTier.FREE
            plan = get_plan(tier)
            cooldown = timedelta(minutes=plan.scan_frequency_minutes)
            if rec.last_scan_at is not None and (now - rec.last_scan_at) < cooldown:
                logger.info(
                    "Skipping tenant=%s sub=%s tier=%s within cooldown (%dm)",
                    tenant_id, subscription_id, tier.value,
                    plan.scan_frequency_minutes,
                )
                skipped += 1
                continue

            try:
                pipeline = await _build_scan_pipeline(
                    subscription_id, db, async_credential,
                    customer_tenant_id=(
                        rec.customer_tenant_id or rec.tenant_id
                    ),
                    provider=rec.provider.value,
                    aws_account_id=rec.aws_account_id,
                    aws_region=rec.aws_region or "us-east-1",
                    gcp_project_id=rec.gcp_project_id,
                )
                result = await pipeline.run(subscription_id, tenant_id=tenant_id)
                logger.info(
                    "Tenant %s sub %s tier=%s scan_id=%s findings=%d",
                    tenant_id, subscription_id, tier.value,
                    result.scan_id, result.findings_count,
                )
                scanned += 1
                # Stamp last_scan_at on success only
                try:
                    await subs_repo.mark_scanned(tenant_id, subscription_id)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Failed to stamp last_scan_at for %s/%s: %s",
                        tenant_id, subscription_id, exc,
                    )
            except Exception as exc:  # noqa: BLE001
                # Phase 3.6: when the customer-tenant credential is
                # rejected (consent revoked, app deleted, or service
                # principal removed) we mark the subscription Disabled
                # so we stop hammering ARM on every tick. The owner
                # can re-enable it from the Settings UI after fixing
                # the grant.
                msg = str(exc)
                auth_failed = any(
                    code in msg
                    for code in (
                        "AADSTS", "401", "403", "Forbidden",
                        "Unauthorized", "AuthenticationFailed",
                    )
                )
                logger.error(
                    "Scan failed for tenant %s sub %s: %s",
                    tenant_id, subscription_id, exc,
                )
                if auth_failed:
                    try:
                        rec.state = "Disabled"
                        await subs_repo.upsert(rec)
                        logger.warning(
                            "Disabled subscription tenant=%s sub=%s due "
                            "to auth failure (consent likely revoked)",
                            tenant_id, subscription_id,
                        )
                    except Exception as inner:  # noqa: BLE001
                        logger.error(
                            "Failed to disable sub %s/%s: %s",
                            tenant_id, subscription_id, inner,
                        )
        logger.info(
            "Timer scan done: scanned=%d skipped_for_cooldown=%d total=%d",
            scanned, skipped, len(records),
        )
    finally:
        await db.close()
        await async_credential.close()


@app.timer_trigger(
    schedule="0 30 2 * * *",
    arg_name="timer",
    run_on_startup=False,
)
async def purge_trigger(timer: func.TimerRequest) -> None:
    """Daily timer that hard-deletes expired soft-deleted subscriptions.

    When a user clicks Remove, the subscription record is soft-deleted
    (``state='Removed'``, ``removed_at`` stamped) but its findings,
    snapshots and remediations are kept for ``subscription_retention_days``
    so a re-link of the same GUID restores the history. This timer runs
    once per day and hard-deletes records whose retention has expired.
    """
    from cloudguardiq.core.config import get_settings
    from cloudguardiq.core.database import CosmosRepository
    from cloudguardiq.subscriptions.repository import SubscriptionsRepository

    settings = get_settings()
    db = CosmosRepository(settings)
    await db.connect()
    try:
        repo = SubscriptionsRepository(
            settings, cosmos_db=db._db if db is not None else None,
        )
        expired = await repo.list_expired_removed(
            settings.subscription_retention_days,
        )
        if not expired:
            logger.info("Purge trigger: no expired soft-deleted subscriptions")
            return

        purged = 0
        for rec in expired:
            try:
                await db.purge_subscription_data(
                    rec.subscription_id, tenant_id=rec.tenant_id,
                )
                await repo.hard_delete(rec.tenant_id, rec.subscription_id)
                purged += 1
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Purge failed for tenant=%s sub=%s: %s",
                    rec.tenant_id, rec.subscription_id, exc,
                )
        logger.info(
            "Purge trigger done: purged=%d total_expired=%d",
            purged, len(expired),
        )
    finally:
        await db.close()


@app.service_bus_queue_trigger(
    arg_name="msg",
    queue_name="findings-queue",
    connection="SERVICE_BUS_CONNECTION",
)
async def ai_worker_trigger(msg: func.ServiceBusMessage) -> None:
    """Service Bus triggered AI worker for processing findings."""
    body = msg.get_body().decode("utf-8")
    logger.info("AI worker received message: %s", msg.message_id)

    worker = None
    db = None
    credential = None
    try:
        worker, db, credential = await _get_ai_worker()
        card = await worker.process_message(body)
        if card is not None:
            logger.info(
                "AI worker generated card %s for message %s",
                card.card_id,
                msg.message_id,
            )
        else:
            logger.warning(
                "AI worker failed to generate card for message %s",
                msg.message_id,
            )
    except Exception as exc:  # noqa: BLE001
        logger.error("AI worker error: %s", exc)
    finally:
        if db is not None:
            await db.close()
        if credential is not None:
            await credential.close()
