"""CloudGuardIQ -- FastAPI application."""

from __future__ import annotations

import logging
import os
import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
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
from cloudguardiq.api import billing as billing_module
from cloudguardiq.api import subscriptions as subscriptions_module
from cloudguardiq.api.auth import TokenPayload, get_tenant_id, verify_token
from cloudguardiq.billing.middleware import TierEnforcementMiddleware
from cloudguardiq.billing.plans import UNLIMITED, get_plan
from cloudguardiq.billing.repository import BillingRepository
from cloudguardiq.billing.stripe_service import StripeService
from cloudguardiq.billing.usage import UsageRepository
from cloudguardiq.core.config import get_settings
from cloudguardiq.core.database import CosmosRepository
from cloudguardiq.core.enums import DataTier, FindingType, Severity, SubscriptionTier
from cloudguardiq.core.models import (
    FindingResult,
    RemediationCard,
    ResourceSnapshot,
    ScanRequest,
    ScanResponse,
)
from cloudguardiq.pipeline.scan_pipeline import ScanResult
from cloudguardiq.policy.engine import PolicyEngine, PolicyRule
from cloudguardiq.subscriptions.repository import SubscriptionsRepository

logger = logging.getLogger(__name__)

_auth = Depends(verify_token)

# ------------------------------------------------------------------
# Application state
# ------------------------------------------------------------------
_repo: CosmosRepository | None = None
_billing_repo: BillingRepository | None = None
_subs_repo: SubscriptionsRepository | None = None
_tier_middleware: TierEnforcementMiddleware | None = None


def get_billing_repo() -> BillingRepository | None:
    """Return the BillingRepository instance (may be None in tests)."""
    return _billing_repo

def get_repo() -> CosmosRepository | None:
    """Return the CosmosRepository instance (may be None in tests)."""
    return _repo


async def _validate_owned_subscription(
    user: TokenPayload, subscription_id: str
) -> str:
    """Ensure the JWT tenant owns `subscription_id` (Phase 2).

    In auth-disabled (dev/test) mode the check is a no-op so that local
    smoke tests and dashboards keep working without registering subs.
    In production mode the route returns `403 subscription_not_linked`
    when the tenant has not added the subscription via /subscriptions.
    """
    settings = get_settings()
    if settings.auth_disabled:
        return subscription_id.lower()
    tenant_id = get_tenant_id(user)
    repo = subscriptions_module._repository  # noqa: SLF001
    if repo is None:
        logger.warning(
            "Subscriptions repo not configured; skipping ownership check"
        )
        return subscription_id.lower()
    record = await repo.get(tenant_id, subscription_id.lower())
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "subscription_not_linked",
                "subscription_id": subscription_id,
            },
        )
    return record.subscription_id


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

    global _billing_repo  # noqa: PLW0603
    _billing_repo = BillingRepository(
        settings,
        cosmos_db=_repo._db if _repo is not None else None,
    )
    global _usage_repo  # noqa: PLW0603
    _usage_repo = UsageRepository(
        settings,
        cosmos_db=_repo._db if _repo is not None else None,
    )
    stripe_service = StripeService(settings)
    billing_module.configure(
        repository=_billing_repo,
        stripe_service=stripe_service,
        invalidate_cache=(
            _tier_middleware.invalidate if _tier_middleware is not None else None
        ),
    )

    global _subs_repo  # noqa: PLW0603
    _subs_repo = SubscriptionsRepository(
        settings,
        cosmos_db=_repo._db if _repo is not None else None,
    )
    subscriptions_module.configure(
        repository=_subs_repo,
        billing_repository=_billing_repo,
        settings=settings,
    )

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
    allow_origins=get_settings().cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Tier enforcement middleware. Uses an in-memory BillingRepository at boot;
# at lifespan startup the billing router is reconfigured to share state with
# the Cosmos-backed repo when available.
_bootstrap_billing_repo = BillingRepository(get_settings(), cosmos_db=None)
_usage_repo: UsageRepository = UsageRepository(get_settings(), cosmos_db=None)
app.add_middleware(
    TierEnforcementMiddleware,
    settings=get_settings(),
    repository=_bootstrap_billing_repo,
)

# Wire bootstrap dependencies so tests that never run lifespan still work.
billing_module.configure(
    repository=_bootstrap_billing_repo,
    stripe_service=StripeService(get_settings()),
)

# Bootstrap subscriptions repo (in-memory) so tests that never run lifespan
# still work. The lifespan hook later swaps in the Cosmos-backed repo.
_bootstrap_subs_repo = SubscriptionsRepository(get_settings(), cosmos_db=None)
subscriptions_module.configure(
    repository=_bootstrap_subs_repo,
    billing_repository=_bootstrap_billing_repo,
    settings=get_settings(),
)

# Billing routes
app.include_router(billing_module.router)
# Subscription management routes (Phase 2)
app.include_router(subscriptions_module.router)


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
                if result is None:
                    return []
                if isinstance(result, list):
                    return result
                return [result]

            return _eval

        engine.register_rule(_wrap())
    return engine


# ------------------------------------------------------------------
# Demo data (used when Cosmos DB has no findings)
# ------------------------------------------------------------------
def _stable_id(key: str) -> str:
    """Generate a deterministic UUID for demo data."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, key))


def _demo_findings() -> list[FindingResult]:
    """Return realistic demo findings for the dashboard."""
    snap_sa = ResourceSnapshot(
        subscription_id="sub-stub",
        resource_group="rg-prod-eastus",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="proddata2024",
        region="eastus",
        data_tier=DataTier.TIER1_NATIVE,
        config={"supportsHttpsTrafficOnly": False, "allowBlobPublicAccess": True},
    )
    snap_nsg = ResourceSnapshot(
        subscription_id="sub-stub",
        resource_group="rg-prod-eastus",
        resource_type="Microsoft.Network/networkSecurityGroups",
        resource_name="nsg-frontend",
        region="eastus",
        data_tier=DataTier.TIER1_NATIVE,
        config={
            "securityRules": [{
                "destinationPortRange": "22",
                "sourceAddressPrefix": "*",
                "access": "Allow",
                "direction": "Inbound",
            }],
        },
    )
    snap_vm = ResourceSnapshot(
        subscription_id="sub-stub",
        resource_group="rg-dev-westus",
        resource_type="Microsoft.Compute/virtualMachines",
        resource_name="vm-dev-idle",
        region="westus2",
        data_tier=DataTier.TIER1_NATIVE,
        cost_monthly=156.0,
        config={"hardwareProfile": {"vmSize": "Standard_D4s_v3"}, "avgCpuPercent": 2.1},
    )
    snap_disk = ResourceSnapshot(
        subscription_id="sub-stub",
        resource_group="rg-dev-westus",
        resource_type="Microsoft.Compute/disks",
        resource_name="disk-orphan-01",
        region="westus2",
        data_tier=DataTier.TIER1_NATIVE,
        cost_monthly=38.40,
        config={"diskState": "Unattached", "diskSizeGB": 512},
    )
    snap_kv = ResourceSnapshot(
        subscription_id="sub-stub",
        resource_group="rg-prod-eastus",
        resource_type="Microsoft.KeyVault/vaults",
        resource_name="kv-prod-secrets",
        region="eastus",
        data_tier=DataTier.TIER1_NATIVE,
        config={"properties": {"enableSoftDelete": False, "enablePurgeProtection": False}},
    )
    snap_sa2 = ResourceSnapshot(
        subscription_id="sub-stub",
        resource_group="rg-staging",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="stagingblobs",
        region="westeurope",
        data_tier=DataTier.TIER1_NATIVE,
        config={"supportsHttpsTrafficOnly": True, "allowBlobPublicAccess": True},
    )
    snap_vm2 = ResourceSnapshot(
        subscription_id="sub-stub",
        resource_group="rg-prod-eastus",
        resource_type="Microsoft.Compute/virtualMachines",
        resource_name="vm-web-prod",
        region="eastus",
        data_tier=DataTier.TIER1_NATIVE,
        config={"storageProfile": {"osDisk": {"managedDisk": None}}},
    )

    findings = [
        FindingResult(
            finding_id=_stable_id("STORAGE-001-proddata2024"),
            rule_id="STORAGE-001",
            rule_name="Storage HTTPS Only",
            severity=Severity.CRITICAL,
            finding_type=FindingType.SECURITY,
            description=(
                "Storage account 'proddata2024' does not enforce HTTPS-only traffic."
                " Data in transit may be intercepted."
            ),
            resource_snapshot=snap_sa,
            evidence={"supportsHttpsTrafficOnly": False},
            compliance_frameworks=["CIS 3.1", "NIST SC-8"],
        ),
        FindingResult(
            finding_id=_stable_id("STORAGE-002-proddata2024"),
            rule_id="STORAGE-002",
            rule_name="Storage Public Access",
            severity=Severity.HIGH,
            finding_type=FindingType.SECURITY,
            description=(
                "Storage account 'proddata2024' allows public blob access."
                " Sensitive data may be exposed."
            ),
            resource_snapshot=snap_sa,
            evidence={"allowBlobPublicAccess": True},
            compliance_frameworks=["CIS 3.7"],
        ),
        FindingResult(
            finding_id=_stable_id("NSG-001-nsg-frontend"),
            rule_id="NSG-001",
            rule_name="NSG Open SSH",
            severity=Severity.CRITICAL,
            finding_type=FindingType.SECURITY,
            description=(
                "NSG 'nsg-frontend' allows SSH (port 22) from any source. High"
                " risk of brute-force attacks."
            ),
            resource_snapshot=snap_nsg,
            evidence={"open_port": 22, "source": "*"},
            compliance_frameworks=["CIS 6.2", "NIST AC-17"],
        ),
        FindingResult(
            finding_id=_stable_id("FINOPS-001-vm-dev-idle"),
            rule_id="FINOPS-001",
            rule_name="Underutilized VM",
            severity=Severity.MEDIUM,
            finding_type=FindingType.FINOPS,
            description=(
                "VM 'vm-dev-idle' has average CPU utilization of 2.1%%. Consider"
                " downsizing or deallocating."
            ),
            resource_snapshot=snap_vm,
            waste_monthly_usd=140.40,
            evidence={"avgCpuPercent": 2.1, "vmSize": "Standard_D4s_v3"},
        ),
        FindingResult(
            finding_id=_stable_id("FINOPS-002-disk-orphan-01"),
            rule_id="FINOPS-002",
            rule_name="Unattached Disk",
            severity=Severity.LOW,
            finding_type=FindingType.FINOPS,
            description=(
                "Disk 'disk-orphan-01' (512 GB) is unattached. Delete to"
                " stop incurring charges."
            ),
            resource_snapshot=snap_disk,
            waste_monthly_usd=38.40,
            evidence={"diskState": "Unattached", "diskSizeGB": 512},
        ),
        FindingResult(
            finding_id=_stable_id("KV-001-kv-prod-secrets"),
            rule_id="KV-001",
            rule_name="Key Vault Soft Delete",
            severity=Severity.HIGH,
            finding_type=FindingType.SECURITY,
            description=(
                "Key Vault 'kv-prod-secrets' does not have soft delete enabled."
                " Accidental deletion is unrecoverable."
            ),
            resource_snapshot=snap_kv,
            evidence={"enableSoftDelete": False},
            compliance_frameworks=["CIS 8.4"],
        ),
        FindingResult(
            finding_id=_stable_id("KV-002-kv-prod-secrets"),
            rule_id="KV-002",
            rule_name="Key Vault Purge Protection",
            severity=Severity.MEDIUM,
            finding_type=FindingType.COMPLIANCE,
            description="Key Vault 'kv-prod-secrets' does not have purge protection enabled.",
            resource_snapshot=snap_kv,
            evidence={"enablePurgeProtection": False},
            compliance_frameworks=["CIS 8.4", "SOC2 CC6.1"],
        ),
        FindingResult(
            finding_id=_stable_id("STORAGE-002-stagingblobs"),
            rule_id="STORAGE-002",
            rule_name="Storage Public Access",
            severity=Severity.HIGH,
            finding_type=FindingType.SECURITY,
            description="Storage account 'stagingblobs' allows public blob access.",
            resource_snapshot=snap_sa2,
            evidence={"allowBlobPublicAccess": True},
            compliance_frameworks=["CIS 3.7"],
        ),
        FindingResult(
            finding_id=_stable_id("VM-001-vm-web-prod"),
            rule_id="VM-001",
            rule_name="VM Unmanaged Disks",
            severity=Severity.MEDIUM,
            finding_type=FindingType.SECURITY,
            description=(
                "VM 'vm-web-prod' uses unmanaged disks. Migrate to managed"
                " disks for better reliability."
            ),
            resource_snapshot=snap_vm2,
            evidence={"managedDisk": None},
        ),
    ]
    for f in findings:
        f.compute_priority_score()
    return findings


_MOCK_TF = (
    'resource "azurerm_storage_account" "example" {\n'
    "  enable_https_traffic_only = true\n}"
)


def _mock_remediation_card(finding: FindingResult) -> RemediationCard:
    """Return a stub RemediationCard for a given finding."""
    return RemediationCard(
        finding_result=finding,
        narrative=f"Remediation: {finding.description}",
        terraform_fix=_MOCK_TF,
        confidence_qualifier="high",
        model_version="gpt-5.1-2025-11-13",
    )


# ------------------------------------------------------------------
# Persistence helpers
# ------------------------------------------------------------------
async def _persist_scan_results(
    repo: CosmosRepository,
    scan_id: str,
    subscription_id: str,
    snapshots: list[ResourceSnapshot],
    findings: list[FindingResult],
    duration: float,
) -> None:
    """Persist snapshots, findings, and scan summary to Cosmos DB."""
    # Save snapshots
    for snap in snapshots:
        try:
            await repo.save_snapshot(snap)
        except Exception as exc:
            logger.warning("Failed to save snapshot %s: %s", snap.id, exc)

    # Save findings
    for finding in findings:
        try:
            await repo.save_finding(finding)
        except Exception as exc:
            logger.warning(
                "Failed to save finding %s: %s",
                finding.finding_id, exc,
            )

    # Save scan summary
    critical = sum(
        1 for f in findings if f.severity == Severity.CRITICAL
    )
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    total_waste = sum(f.waste_monthly_usd for f in findings)
    try:
        await repo.save_scan_result({
            "id": scan_id,
            "type": "scan_result",
            "scan_id": scan_id,
            "subscription_id": subscription_id,
            "status": "completed",
            "resources_scanned": len(snapshots),
            "findings_count": len(findings),
            "critical_count": critical,
            "high_count": high,
            "total_waste_usd": total_waste,
            "duration_seconds": round(duration, 2),
        })
    except Exception as exc:
        logger.warning("Failed to save scan result: %s", exc)

    logger.info(
        "Persisted scan %s: %d snapshots, %d findings",
        scan_id, len(snapshots), len(findings),
    )



# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "version": "0.1.0"}


@app.get("/config")
async def get_config() -> dict[str, Any]:
    """Public client-config endpoint.

    Returns settings the frontend needs to render correctly. ``demo_mode`` is
    true when the API is running with auth disabled (local/dev) and is
    therefore serving canned demo findings; the UI should display a banner.
    """
    settings = get_settings()
    return {
        "demo_mode": bool(settings.auth_disabled),
        "client_id": settings.azure_client_id or "",
        "version": settings.app_version,
    }


@app.post("/scan/trigger")
async def trigger_scan(
    request: ScanRequest,
    user: TokenPayload = _auth,
) -> dict[str, str]:
    """Trigger an async scan for a subscription.

    Enqueues a scan request and returns immediately with a scan_id.
    """
    await _validate_owned_subscription(user, request.subscription_id)
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
    user: TokenPayload = _auth,
) -> ScanResponse:
    """Scan an Azure subscription for security and cost findings."""
    await _validate_owned_subscription(user, request.subscription_id)
    scan_id = str(uuid.uuid4())
    start = time.perf_counter()

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

    # Compute priority scores
    for f in findings:
        f.compute_priority_score()

    # Persist to Cosmos DB
    if repo is not None:
        await _persist_scan_results(
            repo, scan_id, request.subscription_id,
            snapshots, findings, time.perf_counter() - start,
        )

    return ScanResponse(
        subscription_id=request.subscription_id,
        snapshots_count=len(snapshots),
        findings_count=len(findings),
        findings=findings,
    )


@app.get("/findings", response_model=list[FindingResult])
async def list_findings(
    subscription_id: str = Query(default=""),
    limit: int = Query(default=50, ge=1, le=200),
    user: TokenPayload = _auth,
) -> list[FindingResult]:
    """Return FindingResults for a subscription, sorted by priority_score descending."""
    repo = get_repo()
    sub_id = ""
    if subscription_id:
        sub_id = await _validate_owned_subscription(user, subscription_id)
    settings = get_settings()
    tenant_id = None if settings.auth_disabled else get_tenant_id(user)
    if repo is not None and sub_id:
        try:
            findings = await repo.get_findings(sub_id, tenant_id=tenant_id, limit=limit)
            return sorted(
                findings,
                key=lambda f: f.priority_score,
                reverse=True,
            )
        except Exception as exc:
            logger.warning("Failed to query findings from Cosmos: %s", exc)
            return []

    # No subscription selected: return empty in production. Demo data is only
    # served in auth-disabled (local/dev) mode so it cannot leak into a
    # tenant's live dashboard before they have linked a subscription.
    if not settings.auth_disabled:
        return []
    demo = _demo_findings()
    return sorted(demo, key=lambda f: f.priority_score, reverse=True)[:limit]


@app.get("/findings/{finding_id}", response_model=FindingResult)
async def get_finding(
    finding_id: str,
    subscription_id: str = Query(default=""),
    user: TokenPayload = _auth,
) -> FindingResult:
    """Get a single FindingResult by finding ID."""
    repo = get_repo()
    sub_id: str = ""
    if subscription_id:
        sub_id = await _validate_owned_subscription(user, subscription_id)
    settings = get_settings()
    tenant_id = None if settings.auth_disabled else get_tenant_id(user)
    if repo is not None:
        try:
            finding = await repo.get_finding(
                finding_id,
                subscription_id=sub_id or None,
                tenant_id=tenant_id,
            )
            if finding is not None:
                return finding
        except Exception as exc:
            logger.warning("Failed to query finding: %s", exc)

    # Demo fallback for local/dev only
    for f in _demo_findings():
        if f.finding_id == finding_id:
            return f

    raise HTTPException(status_code=404, detail="Finding not found")


@app.get("/findings/{finding_id}/remediation", response_model=RemediationCard)
async def get_finding_remediation(
    finding_id: str,
    _user: TokenPayload = _auth,
) -> RemediationCard:
    """Get a RemediationCard for a finding."""
    repo = get_repo()
    if repo is not None:
        try:
            card = await repo.get_remediation_card(finding_id)
            if card:
                return card
        except Exception as exc:
            logger.warning(
                "Remediation lookup failed for %s: %s", finding_id, exc,
            )

    # Generate mock remediation from demo finding
    for f in _demo_findings():
        if f.finding_id == finding_id:
            return _mock_remediation_card(f)

    raise HTTPException(status_code=404, detail="Finding not found")


@app.post("/findings/{finding_id}/generate-remediation", response_model=RemediationCard)
async def generate_finding_remediation(
    finding_id: str,
    user: TokenPayload = _auth,
) -> RemediationCard:
    """Generate an AI remediation card on-demand for a finding.

    Calls Azure OpenAI GPT directly — does NOT go through Service Bus.
    If a card already exists in Cosmos it is returned immediately.
    """
    repo = get_repo()

    # --- Plan quota: AI remediations per calendar month ---------------
    tenant_id = get_tenant_id(user)
    billing_record = (
        await _billing_repo.get(tenant_id) if _billing_repo is not None else None
    )
    plan = get_plan(
        billing_record.tier if billing_record is not None else SubscriptionTier.FREE,
    )
    ai_cap = plan.max_ai_remediations_per_month
    current_usage = await _usage_repo.get_current(tenant_id)
    if ai_cap != UNLIMITED and current_usage.ai_remediations >= ai_cap:
        raise HTTPException(
            status_code=402,
            detail={
                "error": "upgrade_required",
                "current_tier": plan.tier.value.lower(),
                "limit": "ai_remediations_per_month",
                "cap": ai_cap,
                "current": current_usage.ai_remediations,
            },
        )

    # Return cached card if one exists
    if repo is not None:
        try:
            existing = await repo.get_remediation_card(finding_id)
            if existing is not None:
                return existing
        except Exception as exc:
            logger.warning(
                "Cached remediation lookup failed for %s: %s", finding_id, exc,
            )

    # Load the finding
    finding: FindingResult | None = None
    if repo is not None:
        try:
            finding = await repo.get_finding(finding_id)
        except Exception as exc:
            logger.warning("Failed to load finding %s: %s", finding_id, exc)

    if finding is None:
        for f in _demo_findings():
            if f.finding_id == finding_id:
                finding = f
                break

    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Import AI engine deps up-front so exception handlers can reference them
    try:
        import contextlib

        import openai as _openai
        from azure.identity.aio import (
            DefaultAzureCredential,
            get_bearer_token_provider,
        )

        from cloudguardiq.ai.remediation_engine import (
            AIEngineError,
            RemediationEngine,
        )
    except ImportError as exc:
        logger.error("AI engine import failed: %s", exc)
        raise HTTPException(
            status_code=501,
            detail="AI engine dependencies not installed",
        ) from exc

    settings = get_settings()
    credential: Any = None
    try:
        credential = DefaultAzureCredential()
        token_provider = get_bearer_token_provider(
            credential, "https://cognitiveservices.azure.com/.default",
        )
        endpoint = (
            settings.azure_openai_endpoint
            or os.environ.get("AZURE_OPENAI_ENDPOINT", "")
        )
        if not endpoint:
            raise HTTPException(
                status_code=503,
                detail="Azure OpenAI endpoint not configured",
            )
        openai_client = _openai.AsyncAzureOpenAI(
            azure_endpoint=endpoint,
            azure_ad_token_provider=token_provider,
            api_version="2024-02-15-preview",
        )
        deployment = os.environ.get(
            "AZURE_OPENAI_DEPLOYMENT", settings.azure_openai_deployment,
        )

        engine = RemediationEngine(
            client=openai_client,
            deployment=deployment,
            db=repo,
        )
        card = await engine.generate(finding)
        try:
            await _usage_repo.increment_ai_remediations(tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Usage increment failed for %s: %s", tenant_id, exc)
        return card
    except HTTPException:
        raise
    except AIEngineError as exc:
        logger.error("AI generation failed for %s: %s", finding_id, exc)
        raise HTTPException(
            status_code=502,
            detail=f"AI generation failed: {exc}",
        ) from exc
    except Exception as exc:
        logger.exception("AI generation error for %s", finding_id)
        raise HTTPException(
            status_code=502,
            detail=f"AI generation failed: {exc.__class__.__name__}",
        ) from exc
    finally:
        if credential is not None:
            with contextlib.suppress(Exception):
                await credential.close()


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

    return _MOCK_TF


# /subscriptions endpoints are now served by subscriptions_module.router

