"""CloudGuardIQ -- Azure Functions v4 entry point."""

from __future__ import annotations

import logging
import os

import azure.functions as func

logger = logging.getLogger(__name__)

app = func.FunctionApp()


async def _get_scan_pipeline():
    """Build a ScanPipeline from environment configuration."""
    from azure.identity import DefaultAzureCredential as SyncDefaultAzureCredential
    from azure.identity.aio import DefaultAzureCredential as AsyncDefaultAzureCredential
    from azure.servicebus.aio import ServiceBusClient

    from cloudguardiq.adapters.azure_adapter import AzureAdapter
    from cloudguardiq.core.config import get_settings
    from cloudguardiq.core.database import CosmosRepository
    from cloudguardiq.pipeline.scan_pipeline import ScanPipeline
    from cloudguardiq.policy.engine import PolicyEngine

    settings = get_settings()
    sync_credential = SyncDefaultAzureCredential()
    async_credential = AsyncDefaultAzureCredential()
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "")

    db = CosmosRepository(settings)
    await db.connect()

    adapter = AzureAdapter(
        credential=sync_credential,
        subscription_id=subscription_id,
        db=db,
        async_credential=async_credential,
    )
    policy_engine = PolicyEngine()

    # AI engine (used by worker, not scan pipeline directly)
    ai_engine = None

    # Service Bus sender (managed identity)
    sender = None
    sb_fqns = os.environ.get("SERVICE_BUS_CONNECTION__fullyQualifiedNamespace")  # noqa: SIM112 -- Azure Functions binding requires exact casing
    if sb_fqns:
        sb_client = ServiceBusClient(
            fully_qualified_namespace=sb_fqns,
            credential=async_credential,
        )
        sender = sb_client.get_queue_sender(queue_name="findings-queue")

    return ScanPipeline(
        adapter=adapter,
        policy_engine=policy_engine,
        ai_engine=ai_engine,
        db=db,
        service_bus_sender=sender,
    ), db, async_credential


async def _get_ai_worker():
    """Build an AIWorker from environment configuration."""
    import openai
    from azure.identity.aio import DefaultAzureCredential, get_bearer_token_provider

    from cloudguardiq.ai.remediation_engine import RemediationEngine
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

    return AIWorker(ai_engine=ai_engine, db=db), db, credential


@app.timer_trigger(
    schedule="0 0 */6 * * *",
    arg_name="timer",
    run_on_startup=False,
)
async def scan_trigger(timer: func.TimerRequest) -> None:
    """Timer-triggered scan that runs every 6 hours."""
    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    if not subscription_id:
        logger.error("AZURE_SUBSCRIPTION_ID not set -- skipping scan")
        return

    logger.info("Timer scan triggered for subscription %s", subscription_id)

    pipeline = None
    db = None
    credential = None
    try:
        pipeline, db, credential = await _get_scan_pipeline()
        result = await pipeline.run(subscription_id)
        logger.info(
            "Timer scan completed: scan_id=%s, findings=%d",
            result.scan_id,
            result.findings_count,
        )
    except Exception as exc:
        logger.error("Timer scan failed: %s", exc)
    finally:
        if db is not None:
            await db.close()
        if credential is not None:
            await credential.close()


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
    except Exception as exc:
        logger.error("AI worker error: %s", exc)
    finally:
        if db is not None:
            await db.close()
        if credential is not None:
            await credential.close()
