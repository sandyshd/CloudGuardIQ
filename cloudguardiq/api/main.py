"""CloudGuardIQ -- FastAPI application."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from cloudguardiq.adapters.azure_adapter import AzureAdapter
from cloudguardiq.adapters.native_scanner import NativeScanner
from cloudguardiq.adapters.rules.compute import (
    VMNoEncryptionRule,
    VMUnmanagedDisksRule,
)
from cloudguardiq.adapters.rules.finops import (
    UnattachedDiskRule,
    UnderutilizedVMRule,
)
from cloudguardiq.adapters.rules.keyvault import (
    KeyVaultPurgeProtectionRule,
    KeyVaultSoftDeleteRule,
)
from cloudguardiq.adapters.rules.network import NSGOpenRDPRule, NSGOpenSSHRule
from cloudguardiq.adapters.rules.storage import (
    StorageHttpsOnlyRule,
    StoragePublicAccessRule,
)
from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.core.config import get_settings
from cloudguardiq.core.database import CosmosRepository
from cloudguardiq.core.enums import DataTier, Severity
from cloudguardiq.core.models import (
    FindingResult,
    RemediationCard,
    ResourceSnapshot,
    ScanRequest,
    ScanResponse,
)
from cloudguardiq.pipeline.scan_pipeline import ScanResult
from cloudguardiq.policy.engine import PolicyEngine, PolicyRule

logger = logging.getLogger(__name__)

_auth = Depends(verify_token)

# ------------------------------------------------------------------
# Application state
# ------------------------------------------------------------------
_repo: CosmosRepository | None = None


def get_repo() -> CosmosRepository | None:
    """Return the CosmosRepository instance (may be None in tests)."""
    return _repo


@asynccontextmanager
async def lifespan(
    application: FastAPI,
) -> AsyncGenerator[None, None]:
    """Startup / shutdown lifecycle for the FastAPI app."""
    global _repo  # noqa: PLW0603
    settings = get_settings()
    logger.info("CloudGuardIQ %s starting up", settings.app_version)

    if settings.cosmos_endpoint:
        _repo = CosmosRepository(settings)
        await _repo.connect()

    yield

    if _repo is not None:
        await _repo.close()
    logger.info("CloudGuardIQ shutting down")


app = FastAPI(
    title="CloudGuardIQ",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------
# Request logging middleware
# ------------------------------------------------------------------
@app.middleware("http")
async def request_logging_middleware(
    request: Request,
    call_next: Any,
) -> Response:
    """Log method, path, status code, and duration."""
    start = time.perf_counter()
    response: Response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    logger.info(
        "%s %s -> %s (%.1fms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def _build_scanner() -> NativeScanner:
    """Build a NativeScanner with all registered rules."""
    scanner = NativeScanner()
    rules: list[Any] = [
        StorageHttpsOnlyRule(),
        StoragePublicAccessRule(),
        NSGOpenSSHRule(),
        NSGOpenRDPRule(),
        VMUnmanagedDisksRule(),
        VMNoEncryptionRule(),
        KeyVaultSoftDeleteRule(),
        KeyVaultPurgeProtectionRule(),
        UnderutilizedVMRule(),
        UnattachedDiskRule(),
    ]
    for rule in rules:
        scanner.register(rule)
    return scanner


def _build_policy_engine(scanner: NativeScanner) -> PolicyEngine:
    """Build a PolicyEngine backed by native scanner rules."""
    engine = PolicyEngine()
    for rule in scanner._rules:

        def _wrap(r: Any = rule) -> PolicyRule:
            def _eval(snap: ResourceSnapshot) -> list[FindingResult]:
                result = r.evaluate(snap)
                return [result] if result is not None else []

            return _eval

        engine.register_rule(_wrap())
    return engine


# ------------------------------------------------------------------
# Mock data helpers (stubs until real Cosmos integration)
# ------------------------------------------------------------------
_MOCK_TF = (
    'resource "azurerm_storage_account" "example" {\n'
    "  enable_https_traffic_only = true\n}"
)


def _mock_remediation_card(card_id: str) -> RemediationCard:
    """Return a stub RemediationCard for development."""
    return RemediationCard(
        card_id=card_id,
        finding_result=FindingResult(
            finding_id="finding-stub",
            rule_id="STORAGE-001",
            rule_name="Storage HTTPS Only",
            severity=Severity.HIGH,
            description="Storage account does not enforce HTTPS.",
            resource_snapshot=ResourceSnapshot(
                subscription_id="sub-stub",
                resource_group="rg-stub",
                resource_type="Microsoft.Storage/storageAccounts",
                resource_name="sa-stub",
                region="eastus",
                data_tier=DataTier.TIER1_NATIVE,
            ),
        ),
        narrative="Enable HTTPS-only traffic on the storage account.",
        terraform_fix=_MOCK_TF,
        confidence_qualifier="high",
        model_version="gpt-5.1-2025-11-13",
    )


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "version": "0.1.0"}


@app.post("/scan/trigger")
async def trigger_scan(
    request: ScanRequest,
    _user: TokenPayload = _auth,
) -> dict[str, str]:
    """Trigger an async scan for a subscription.

    Enqueues a scan request and returns immediately with a scan_id.
    """
    scan_id = str(uuid.uuid4())
    logger.info(
        "Scan triggered: %s for sub %s",
        scan_id,
        request.subscription_id,
    )
    # Persist scan intent to Cosmos DB if available
    repo = get_repo()
    if repo is not None:
        try:
            await repo.save_scan_result({
                "id": scan_id,
                "partition_key": request.subscription_id,
                "type": "scan_result",
                "scan_id": scan_id,
                "subscription_id": request.subscription_id,
                "status": "queued",
                "resources_scanned": 0,
                "findings_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "total_waste_usd": 0.0,
                "duration_seconds": 0.0,
            })
        except Exception as exc:
            logger.warning("Failed to persist scan request: %s", exc)

    return {"scan_id": scan_id, "status": "queued"}


@app.get("/scan/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    _user: TokenPayload = _auth,
) -> ScanResult:
    """Return the status of a scan by scan_id."""
    repo = get_repo()
    if repo is not None:
        try:
            item = await repo.get_scan_result(scan_id)
            if item is not None:
                return ScanResult.model_validate(item)
        except Exception as exc:
            logger.warning("Failed to query scan status: %s", exc)

    raise HTTPException(status_code=404, detail="Scan not found")


@app.post("/scan", response_model=ScanResponse)
async def scan_subscription(
    request: ScanRequest,
    _user: TokenPayload = _auth,
) -> ScanResponse:
    """Scan an Azure subscription for security and cost findings."""
    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    except Exception:
        credential = None
    repo = get_repo()
    adapter = AzureAdapter(
        credential=credential,
        subscription_id=request.subscription_id,
        db=repo,
    ) if credential and repo else None
    scanner = _build_scanner()
    engine = _build_policy_engine(scanner)

    if adapter is not None:
        try:
            snapshots = await adapter.list_resources(
                request.subscription_id,
            )
        except Exception as exc:
            logger.error('Failed to list resources: %%s', exc)
            raise HTTPException(
                status_code=502,
                detail='Failed to list Azure resources',
            ) from exc
        snapshots = await adapter.enrich_with_defender(snapshots)
    else:
        snapshots = []
    findings: list[FindingResult] = engine.evaluate(snapshots)

    return ScanResponse(
        subscription_id=request.subscription_id,
        snapshots_count=len(snapshots),
        findings_count=len(findings),
        findings=findings,
    )


@app.get("/findings")
async def list_findings(
    subscription_id: str = Query(default="sub-stub"),
    limit: int = Query(default=50, ge=1, le=200),
    _user: TokenPayload = _auth,
) -> list[RemediationCard]:
    """Return RemediationCards sorted by priority_score descending."""
    repo = get_repo()
    if repo is not None:
        findings = await repo.get_findings(
            subscription_id, limit=limit,
        )
        cards: list[RemediationCard] = []
        for f in findings:
            card = await repo.get_remediation_card(f.finding_id)
            if card:
                cards.append(card)
        # Sort by priority_score descending
        cards.sort(
            key=lambda c: c.finding_result.priority_score if c.finding_result else 0.0,
            reverse=True,
        )
        return cards
    return [_mock_remediation_card(str(uuid.uuid4()))]


@app.get("/findings/{finding_id}")
async def get_finding(
    finding_id: str,
    _user: TokenPayload = _auth,
) -> RemediationCard:
    """Get a single RemediationCard by finding ID."""
    repo = get_repo()
    if repo is not None:
        card = await repo.get_remediation_card(finding_id)
        if card:
            return card
        raise HTTPException(
            status_code=404, detail="Finding not found",
        )
    return _mock_remediation_card(finding_id)


@app.get(
    "/findings/{finding_id}/terraform",
    response_class=PlainTextResponse,
)
async def get_finding_terraform(
    finding_id: str,
    _user: TokenPayload = _auth,
) -> str:
    """Return plain-text Terraform fix for a finding."""
    repo = get_repo()
    if repo is not None:
        card = await repo.get_remediation_card(finding_id)
        if card:
            return card.terraform_fix
        raise HTTPException(
            status_code=404, detail="Finding not found",
        )
    card = _mock_remediation_card(finding_id)
    return card.terraform_fix


@app.get("/subscriptions")
async def list_subscriptions(
    _user: TokenPayload = _auth,
) -> list[dict[str, str]]:
    """List connected subscriptions (stub)."""
    return [
        {
            "subscription_id": "sub-stub",
            "name": "Dev Subscription",
            "state": "Enabled",
        },
    ]
