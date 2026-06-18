"""CloudGuardIQ -- FastAPI application."""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from azure.servicebus import ServiceBusMessage as MessageBody
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from cloudguardiq.adapters.azure.adapter import AzureAdapter
from cloudguardiq.adapters.native_scanner import NativeScanner
from cloudguardiq.adapters.rules.azure.compute import (
    VMNoEncryptionRule,
    VMUnmanagedDisksRule,
)
from cloudguardiq.adapters.rules.azure.finops import (
    UnattachedDiskRule,
    UnderutilizedVMRule,
)
from cloudguardiq.adapters.rules.azure.keyvault import (
    KeyVaultPurgeProtectionRule,
    KeyVaultSoftDeleteRule,
)
from cloudguardiq.adapters.rules.azure.network import NSGOpenRDPRule, NSGOpenSSHRule
from cloudguardiq.adapters.rules.azure.storage import (
    StorageHttpsOnlyRule,
    StoragePublicAccessRule,
)
from cloudguardiq.api import billing as billing_module
from cloudguardiq.api import subscriptions as subscriptions_module
from cloudguardiq.api.auth import TokenPayload, get_tenant_id, verify_token
from cloudguardiq.auth.customer_credential import build_default_factory
from cloudguardiq.billing.middleware import TierEnforcementMiddleware
from cloudguardiq.billing.pricing import (
    PricingService,
    configure_pricing_service,
    get_pricing_service,
)
from cloudguardiq.billing.quota import (
    check_ai_quota,
    check_scan_frequency_quota,
    record_ai_remediation,
)
from cloudguardiq.billing.repository import BillingRepository
from cloudguardiq.billing.stripe_service import StripeService
from cloudguardiq.billing.usage import UsageRepository
from cloudguardiq.compliance.scorecard import (
    FrameworkScore as ComplianceFrameworkScore,
)
from cloudguardiq.compliance.scorecard import (
    compute_scorecard as compute_compliance_scorecard,
)
from cloudguardiq.core.config import get_settings
from cloudguardiq.core.database import CosmosRepository
from cloudguardiq.core.enums import DataTier, FindingStatus, FindingType, Severity
from cloudguardiq.core.models import (
    FindingResult,
    RemediationCard,
    ResourceSnapshot,
    ScanRequest,
    ScanResponse,
)
from cloudguardiq.core.observability import (
    bind_context,
    install_context_filter,
)
from cloudguardiq.onboarding.audit_event_repository import AuditEventRepository
from cloudguardiq.onboarding.cloud_connection_repository import CloudConnectionRepository
from cloudguardiq.onboarding.credential_ref_repository import CredentialRefRepository
from cloudguardiq.pipeline.scan_pipeline import ScanPipeline
from cloudguardiq.policy.engine import (
    PolicyEngine,
    PolicyRule,
)
from cloudguardiq.posture.score import (
    PostureScore,
    compute_posture_score,
)
from cloudguardiq.subscriptions.repository import SubscriptionsRepository
from cloudguardiq.tenants.consent_repository import TenantConsentRepository
from cloudguardiq.tenants.onboarding_session_repository import (
    OnboardingSessionRepository,
)

logger = logging.getLogger(__name__)

# Install the request-scoped context filter on the
# root logger so every log line carries tenant_id / subscription_id /
# request_id when a request is in flight.
install_context_filter()

_auth = Depends(verify_token)

# ------------------------------------------------------------------
# Application state
# ------------------------------------------------------------------
_repo: CosmosRepository | None = None
_billing_repo: BillingRepository | None = None
_subs_repo: SubscriptionsRepository | None = None
_consent_repo: TenantConsentRepository | None = None
_onboarding_session_repo: OnboardingSessionRepository | None = None
_cloud_connection_repo: CloudConnectionRepository | None = None
_credential_ref_repo: CredentialRefRepository | None = None
_audit_event_repo: AuditEventRepository | None = None
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

    global _subs_repo, _consent_repo, _onboarding_session_repo  # noqa: PLW0603
    global _cloud_connection_repo, _credential_ref_repo, _audit_event_repo  # noqa: PLW0603
    _subs_repo = SubscriptionsRepository(
        settings,
        cosmos_db=_repo._db if _repo is not None else None,
    )
    _consent_repo = TenantConsentRepository(
        settings,
        cosmos_db=_repo._db if _repo is not None else None,
    )
    _onboarding_session_repo = OnboardingSessionRepository(
        settings,
        cosmos_db=_repo._db if _repo is not None else None,
    )
    _cloud_connection_repo = CloudConnectionRepository(
        settings,
        cosmos_db=_repo._db if _repo is not None else None,
    )
    _credential_ref_repo = CredentialRefRepository(
        settings,
        cosmos_db=_repo._db if _repo is not None else None,
    )
    _audit_event_repo = AuditEventRepository(
        settings,
        cosmos_db=_repo._db if _repo is not None else None,
    )
    subscriptions_module.configure(
        repository=_subs_repo,
        billing_repository=_billing_repo,
        settings=settings,
        consent_repository=_consent_repo,
        onboarding_session_repository=_onboarding_session_repo,
        credential_factory=build_default_factory(settings),
        cosmos_repository=_repo,
    )
    from cloudguardiq.api import onboarding_v1 as onboarding_v1_module

    onboarding_v1_module.configure(
        settings=settings,
        cloud_connection_repository=_cloud_connection_repo,
        credential_ref_repository=_credential_ref_repo,
        audit_event_repository=_audit_event_repo,
    )

    # Re-wire the reports service so its repository shares the live
    # Cosmos connection (the bootstrap service uses in-memory storage).
    reports_module.configure(
        service=_build_reports_service(_repo),
        validate_owned_subscription=_validate_owned_subscription,
        get_repo=get_repo,
        get_providers_for_scope=_providers_for_scope,
    )

    # Wire the Azure Retail Prices service. Warmup pulls the last-known
    # cache from Cosmos so the very first scan after a cold start has
    # live prices; the refresh runs in the background so startup is not
    # blocked on a public-internet call.
    pricing_service = PricingService(repo=_repo)
    configure_pricing_service(pricing_service)
    try:
        await pricing_service.warmup()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Pricing warmup failed: %s", exc)
    if pricing_service.is_stale():
        asyncio.create_task(pricing_service.refresh())

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
_bootstrap_consent_repo = TenantConsentRepository(
    get_settings(), cosmos_db=None,
)
_bootstrap_onboarding_session_repo = OnboardingSessionRepository(
    get_settings(), cosmos_db=None,
)
_bootstrap_cloud_connection_repo = CloudConnectionRepository(get_settings(), cosmos_db=None)
_bootstrap_credential_ref_repo = CredentialRefRepository(get_settings(), cosmos_db=None)
_bootstrap_audit_event_repo = AuditEventRepository(get_settings(), cosmos_db=None)
subscriptions_module.configure(
    repository=_bootstrap_subs_repo,
    billing_repository=_bootstrap_billing_repo,
    settings=get_settings(),
    consent_repository=_bootstrap_consent_repo,
    onboarding_session_repository=_bootstrap_onboarding_session_repo,
)

# Billing routes
app.include_router(billing_module.router)
# Subscription management routes (Phase 2)
app.include_router(subscriptions_module.router)
# Onboarding info (Phase 2.8 -- surfaces MSI principal id for RBAC grant)
from cloudguardiq.api import onboarding as onboarding_module  # noqa: E402
from cloudguardiq.api import onboarding_v1 as onboarding_v1_module  # noqa: E402

onboarding_v1_module.configure(
    settings=get_settings(),
    cloud_connection_repository=_bootstrap_cloud_connection_repo,
    credential_ref_repository=_bootstrap_credential_ref_repo,
    audit_event_repository=_bootstrap_audit_event_repo,
)

app.include_router(onboarding_module.router)
app.include_router(onboarding_v1_module.router)
app.include_router(onboarding_v1_module.cloud_connections_router)

# Compliance report routes (Phase 5.1)
from cloudguardiq.api import reports as reports_module  # noqa: E402
from cloudguardiq.reports import (  # noqa: E402
    BlobReportStorage,
    ComplianceReportGenerator,
    InMemoryReportStorage,
    ReportsRepository,
    ReportsService,
)


def _build_reports_service(cosmos_repo: CosmosRepository | None) -> ReportsService:
    """Construct the ReportsService, picking a storage backend by config."""
    settings = get_settings()
    account_url = getattr(settings, "azure_storage_account_url", "") or ""
    container = getattr(settings, "reports_blob_container", "") or "cloudguardiq-reports"
    storage: BlobReportStorage | InMemoryReportStorage
    if account_url:
        storage = BlobReportStorage(
            account_url=account_url,
            container=container,
        )
    else:
        storage = InMemoryReportStorage()
    return ReportsService(
        generator=ComplianceReportGenerator(),
        storage=storage,
        repository=ReportsRepository(cosmos_repo),
    )


_bootstrap_reports_service = _build_reports_service(None)
# ``_providers_for_scope`` is defined later in this module; bootstrap leaves it
# unset and the lifespan handler re-configures with the live helper.
reports_module.configure(
    service=_bootstrap_reports_service,
    validate_owned_subscription=_validate_owned_subscription,
    get_repo=get_repo,
)
app.include_router(reports_module.router)


# ------------------------------------------------------------------
# Request logging middleware
# ------------------------------------------------------------------
@app.middleware("http")
async def request_logging_middleware(
    request: Request,
    call_next: Any,
) -> Response:
    """Log method, path, status code, and duration.

    Also binds a request id (echoed in the ``X-Request-Id`` response
    header so users can quote it in support tickets) and -- when the
    caller already proved a JWT -- the tenant id, so every downstream
    log line is searchable by tenant in App Insights.
    """
    incoming_id = request.headers.get("x-request-id")
    request_id = incoming_id or uuid.uuid4().hex[:16]
    bind_context(request_id=request_id)

    # Best-effort tenant binding. We avoid full JWT verification here
    # because that costs a JWKS call; the unverified tid claim is good
    # enough for log enrichment and never used for authz.
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        try:
            import base64
            import json
            parts = auth.split(".", 2)
            if len(parts) >= 2:
                pad = "=" * (-len(parts[1]) % 4)
                payload = json.loads(
                    base64.urlsafe_b64decode(parts[1] + pad)
                )
                tid = payload.get("tid")
                if isinstance(tid, str) and tid:
                    bind_context(tenant_id=tid)
        except Exception:
            # Malformed token -- log enrichment is best-effort, never fatal.
            pass

    start = time.perf_counter()
    response: Response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Request-Id"] = request_id
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
async def _enforce_scan_frequency(
    user: TokenPayload, subscription_id: str,
) -> None:
    """Raise HTTP 429 if the tenant's plan-tier scan cadence has not elapsed.

    Free=daily, Starter=hourly, Enterprise=15-min. The check is best-effort
    -- a missing billing repo or a Cosmos query failure must never block a
    legitimate scan, so callers degrade open. The Retry-After header is
    set so the frontend can render a precise countdown.
    """
    settings = get_settings()
    if settings.auth_disabled or _billing_repo is None:
        return
    tenant_id = get_tenant_id(user)
    repo = get_repo()
    quota = await check_scan_frequency_quota(
        tenant_id,
        subscription_id,
        billing_repo=_billing_repo,
        repo=repo,
    )
    if quota.allowed:
        return
    detail = quota.to_detail()
    detail["error"] = "scan_cooldown"
    raise HTTPException(
        status_code=429,
        detail=detail,
        headers={"Retry-After": str(max(1, quota.retry_after_seconds))},
    )


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "version": "0.1.0"}


@app.get("/health/pricing")
async def health_pricing(_user: TokenPayload = _auth) -> dict[str, Any]:
    """Return Azure Retail Prices cache state.

    Useful operationally to confirm the Retail Prices API integration is
    populating the cache. The endpoint reports the last refresh timestamp,
    staleness flag, and every cached (sku, region) -> USD/month entry so an
    operator can see at a glance whether prices were sourced from Azure or
    fell back to a bundled default.
    """
    import time as _time

    svc = get_pricing_service()
    entries = [
        {"sku": sku, "region": region, "price_usd_monthly": price}
        for (sku, region), price in sorted(svc._cache.items())  # noqa: SLF001
    ]
    last_ts = svc._last_refresh_ts  # noqa: SLF001
    return {
        "source": "azure_retail_prices",
        "endpoint": "https://prices.azure.com/api/retail/prices",
        "last_refresh_ts": int(last_ts) if last_ts else None,
        "last_refresh_age_seconds": (
            int(_time.time() - last_ts) if last_ts else None
        ),
        "is_stale": svc.is_stale(),
        "entries_count": len(entries),
        "entries": entries,
    }


@app.post("/health/pricing/refresh")
async def health_pricing_refresh(
    _user: TokenPayload = _auth,
) -> dict[str, Any]:
    """Force-refresh the Retail Prices cache (admin / debug helper)."""
    svc = get_pricing_service()
    await svc.refresh()
    return {
        "status": "refreshed",
        "entries_count": len(svc._cache),  # noqa: SLF001
    }



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
    from azure.identity.aio import DefaultAzureCredential as AsyncDefaultAzureCredential
    from azure.servicebus.aio import ServiceBusClient

    from cloudguardiq.core.models import ManualScanJob

    await _validate_owned_subscription(user, request.subscription_id)
    await _enforce_scan_frequency(user, request.subscription_id)

    tenant_id = "" if get_settings().auth_disabled else get_tenant_id(user)
    requested_by = str(getattr(user, "oid", "") or "")
    scan_id = str(uuid.uuid4())
    queued_at = datetime.now(timezone.utc)
    max_attempts = int(os.environ.get("MANUAL_SCAN_MAX_ATTEMPTS", "3"))

    bind_context(
        subscription_id=request.subscription_id,
        scan_id=scan_id,
        tenant_id=tenant_id,
        provider="azure",
    )
    logger.info(
        "manual_scan_queued scan_id=%s subscription_id=%s tenant_id=%s requested_by=%s",
        scan_id,
        request.subscription_id,
        tenant_id,
        requested_by,
    )

    repo = get_repo()
    if repo is not None:
        try:
            await repo.save_scan_result({
                "id": scan_id,
                "type": "scan_result",
                "scan_id": scan_id,
                "subscription_id": request.subscription_id,
                "tenant_id": tenant_id,
                "status": "queued",
                "queued_at": queued_at.isoformat(),
                "started_at": None,
                "completed_at": None,
                "resources_scanned": 0,
                "findings_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "total_waste_usd": 0.0,
                "duration_seconds": 0.0,
                "error": "",
                "partial_enrichment": False,
                "enrichment_note": "",
                "retries_attempted": 0,
                "max_attempts": max_attempts,
            })
        except Exception as exc:
            logger.warning("Failed to persist queued manual scan %s: %s", scan_id, exc)

    # Accept either casing of the Service Bus namespace env var. The Azure
    # Functions binding convention provisions the camelCase form
    # (SERVICE_BUS_CONNECTION__fullyQualifiedNamespace); the Container App
    # that hosts this API runs on Linux where env var names are
    # case-sensitive, so reading only one casing previously left queuing
    # silently disabled and the manual_scan_worker never fired.
    sb_fqns = os.environ.get(
        "SERVICE_BUS_CONNECTION__FULLYQUALIFIEDNAMESPACE"
    ) or os.environ.get(
        "SERVICE_BUS_CONNECTION__fullyQualifiedNamespace"  # noqa: SIM112
    )
    if not sb_fqns:
        logger.warning(
            "manual_scan_queue_unavailable scan_id=%s subscription_id=%s tenant_id=%s",
            scan_id,
            request.subscription_id,
            tenant_id,
        )
        return {"scan_id": scan_id, "status": "queued"}

    credential = AsyncDefaultAzureCredential()
    try:
        async with ServiceBusClient(
            fully_qualified_namespace=sb_fqns,
            credential=credential,
        ) as client, client.get_queue_sender(queue_name="manual-scans") as sender:
            job = ManualScanJob(
                scan_id=scan_id,
                subscription_id=request.subscription_id,
                tenant_id=tenant_id,
                requested_by=requested_by,
                queued_at=queued_at,
                include_cost=request.include_cost,
                attempt_count=0,
                max_attempts=max_attempts,
            )
            msg = MessageBody(job.model_dump_json().encode("utf-8"))
            msg.message_id = scan_id
            await sender.send_messages(msg)
            logger.info(
                "manual_scan_enqueued scan_id=%s subscription_id=%s tenant_id=%s",
                scan_id,
                request.subscription_id,
                tenant_id,
            )
    except Exception as exc:
        logger.error(
            "manual_scan_enqueue_failed scan_id=%s subscription_id=%s tenant_id=%s error=%s",
            scan_id,
            request.subscription_id,
            tenant_id,
            exc,
        )
        if repo is not None:
            try:
                failed_at = datetime.now(timezone.utc)
                await repo.save_scan_result({
                    "id": scan_id,
                    "type": "scan_result",
                    "scan_id": scan_id,
                    "subscription_id": request.subscription_id,
                    "tenant_id": tenant_id,
                    "status": "failed",
                    "queued_at": queued_at.isoformat(),
                    "started_at": None,
                    "completed_at": failed_at.isoformat(),
                    "duration_seconds": 0.0,
                    "error": f"Failed to enqueue scan job: {exc}",
                    "partial_enrichment": False,
                    "enrichment_note": "",
                    "retries_attempted": 0,
                    "max_attempts": max_attempts,
                })
            except Exception as persist_exc:
                logger.warning("Failed to persist enqueue failure for %s: %s", scan_id, persist_exc)
        return {"scan_id": scan_id, "status": "failed"}
    finally:
        await credential.close()

    return {"scan_id": scan_id, "status": "queued"}


@app.get("/scan/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    _user: TokenPayload = _auth,
) -> dict[str, Any]:
    """Return the status payload for a scan by scan_id."""
    repo = get_repo()
    if repo is not None:
        try:
            item = await repo.get_scan_result(scan_id)
            if item is not None:
                status_val = str(item.get("status") or "").lower()
                if not status_val:
                    duration = float(item.get("duration_seconds") or 0.0)
                    status_val = "completed" if duration > 0 else "queued"
                    item["status"] = status_val

                for ts_key in ("queued_at", "started_at", "completed_at"):
                    item.setdefault(ts_key, None)

                if status_val in {"queued", "running"}:
                    timeout_seconds = int(os.environ.get("MANUAL_SCAN_TIMEOUT_SECONDS", "900"))
                    reference_raw = item.get("started_at") or item.get("queued_at")
                    if isinstance(reference_raw, str) and reference_raw:
                        try:
                            started = datetime.fromisoformat(reference_raw.replace("Z", "+00:00"))
                            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
                            if elapsed > timeout_seconds:
                                item["status"] = "timed_out"
                                item["completed_at"] = datetime.now(timezone.utc).isoformat()
                                item["duration_seconds"] = round(float(elapsed), 3)
                                item["error"] = (
                                    item.get("error")
                                    or "Scan timed out in background worker"
                                )
                                try:
                                    await repo.save_scan_result(item)
                                except Exception as persist_exc:
                                    logger.warning(
                                        "Failed to persist timed_out status for scan_id=%s: %s",
                                        scan_id,
                                        persist_exc,
                                    )
                        except ValueError:
                            logger.warning(
                                "Invalid timestamp in scan status for scan_id=%s",
                                scan_id,
                            )

                return item
        except Exception as exc:
            logger.warning("Failed to query scan status for scan_id=%s: %s", scan_id, exc)

    raise HTTPException(status_code=404, detail="Scan not found")


@app.post("/scan", response_model=ScanResponse)
async def scan_subscription(
    request: ScanRequest,
    user: TokenPayload = _auth,
) -> ScanResponse:
    """Scan an Azure subscription for security and cost findings."""
    try:
        return await asyncio.wait_for(
            _scan_subscription_impl(request, user), timeout=180.0
        )
    except TimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail="Scan operation timed out after 3 minutes; "
            "too many resources or slow cloud APIs",
        ) from exc


async def _scan_subscription_impl(
    request: ScanRequest,
    user: TokenPayload,
) -> ScanResponse:
    """Implementation of scan_subscription with 180-second timeout.

    Delegates the actual scan to the shared ``ScanPipeline`` -- the same
    orchestrator used by the timer (``scan_trigger``) and the manual worker
    (``manual_scan_worker``). Keeping this interactive endpoint on the
    pipeline means scan logic (tiered enrichment, policy/Defender merge,
    dedup, persistence, and the auto-resolve sweep) lives in exactly one
    place instead of being re-implemented here.
    """
    await _validate_owned_subscription(user, request.subscription_id)
    await _enforce_scan_frequency(user, request.subscription_id)
    scan_id = str(uuid.uuid4())
    # Enrich every log line emitted while this scan runs with the scan
    # identifiers so a single Application Insights query (`scan_id == X`)
    # returns the full timeline of the scan.
    bind_context(
        subscription_id=request.subscription_id,
        scan_id=scan_id,
        provider="azure",
    )

    settings_obj = get_settings()
    tenant_id_for_scan = (
        "" if settings_obj.auth_disabled else get_tenant_id(user)
    )

    repo = get_repo()
    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    except Exception:
        credential = None

    adapter = AzureAdapter(
        credential=credential,
        subscription_id=request.subscription_id,
        db=repo,
    ) if credential and repo else None

    # Degraded path: without credentials or a database there is nothing to
    # scan. Record a completed (empty) result so the UI reflects the attempt
    # and return -- never run the pipeline against a missing adapter.
    if adapter is None or repo is None:
        if repo is not None:
            try:
                await repo.save_scan_result({
                    "id": scan_id,
                    "type": "scan_result",
                    "scan_id": scan_id,
                    "subscription_id": request.subscription_id,
                    "status": "completed",
                    "resources_scanned": 0,
                    "findings_count": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "total_waste_usd": 0.0,
                    "duration_seconds": 0.0,
                })
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to save scan result: %s", exc)
        return ScanResponse(
            subscription_id=request.subscription_id,
            snapshots_count=0,
            findings_count=0,
            findings=[],
        )

    # Real scan: delegate to the shared pipeline. tenant_id flows through so
    # snapshots and findings are stamped for tenant isolation end-to-end.
    scanner = _build_scanner()
    engine = _build_policy_engine(scanner)
    pipeline = ScanPipeline(
        adapter=adapter,
        policy_engine=engine,
        ai_engine=None,
        db=repo,
        auto_generate_ai=False,
    )
    result = await pipeline.run(
        request.subscription_id, tenant_id=tenant_id_for_scan,
    )

    # Stamp last_scan_at on the subscription record so the UI shows the real
    # last-scan time from the database on every page load -- not just right
    # after clicking "Run Scan". Best-effort: a missing record or a Cosmos
    # hiccup must never fail the scan.
    if _subs_repo is not None:
        try:
            await _subs_repo.mark_scanned(
                tenant_id_for_scan, request.subscription_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to stamp last_scan_at for %s: %s",
                request.subscription_id, exc,
            )

    return ScanResponse(
        subscription_id=request.subscription_id,
        snapshots_count=result.resources_scanned,
        findings_count=result.findings_count,
        findings=pipeline.last_findings,
    )


@app.get("/findings", response_model=list[FindingResult])
async def list_findings(
    subscription_id: str = Query(default=""),
    limit: int = Query(default=50, ge=1, le=5000),
    from_date: str | None = Query(default=None),
    to_date: str | None = Query(default=None),
    user: TokenPayload = _auth,
) -> list[FindingResult]:
    """Return FindingResults for a subscription, sorted by priority_score descending."""
    repo = get_repo()
    sub_id = ""
    if subscription_id:
        sub_id = await _validate_owned_subscription(user, subscription_id)
        bind_context(subscription_id=sub_id, provider="azure")
    settings = get_settings()
    tenant_id = None if settings.auth_disabled else get_tenant_id(user)
    if repo is not None and sub_id:
        try:
            findings = await repo.get_findings(
                sub_id,
                tenant_id=tenant_id,
                limit=limit,
            )
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


@app.get("/resources", response_model=list[ResourceSnapshot])
async def list_resources(
    subscription_id: str = Query(default=""),
    limit: int = Query(default=1000, ge=1, le=5000),
    user: TokenPayload = _auth,
) -> list[ResourceSnapshot]:
    """Return ResourceSnapshots for a subscription, costliest first.

    Reads persisted snapshots produced by the most recent scan -- never calls
    cloud provider APIs directly (that stays inside AdapterBase). A Cosmos
    failure degrades gracefully to an empty list.
    """
    repo = get_repo()
    sub_id = ""
    if subscription_id:
        sub_id = await _validate_owned_subscription(user, subscription_id)
        bind_context(subscription_id=sub_id, provider="azure")
    settings = get_settings()
    tenant_id = None if settings.auth_disabled else get_tenant_id(user)
    if repo is not None and sub_id:
        try:
            return await repo.get_snapshots(
                sub_id,
                tenant_id=tenant_id,
                limit=limit,
            )
        except Exception as exc:
            logger.warning("Failed to query snapshots from Cosmos: %s", exc)
            return []

    # No subscription selected: empty in production. Demo data only in
    # auth-disabled (local/dev) mode so it cannot leak into a live tenant.
    if not settings.auth_disabled:
        return []
    return [f.resource_snapshot for f in _demo_findings() if f.resource_snapshot][:limit]


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


class FindingActionRequest(BaseModel):
    """Body for POST /findings/{id}/resolve|snooze|apply.

    The ``subscription_id`` is required so the route can hit the
    findings container's partition key directly. Without it the
    handler would fall back to a cross-partition scan.
    """

    subscription_id: str
    days: int = 7  # only used by /snooze


async def _mutate_finding_status(
    finding_id: str,
    body: FindingActionRequest,
    user: TokenPayload,
    new_status: FindingStatus,
    extras: dict[str, Any],
) -> FindingResult:
    """Shared body for resolve/snooze/apply -- validates ownership and
    delegates to the repository's atomic update method."""
    sub_id = await _validate_owned_subscription(user, body.subscription_id)
    settings = get_settings()
    tenant_id = "" if settings.auth_disabled else get_tenant_id(user)
    bind_context(subscription_id=sub_id, provider="azure")

    repo = get_repo()
    if repo is None:
        raise HTTPException(
            status_code=503,
            detail="Persistence layer unavailable",
        )
    updated = await repo.update_finding_status(
        finding_id=finding_id,
        subscription_id=sub_id,
        tenant_id=tenant_id,
        status=new_status.value,
        extras=extras,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return updated


@app.post("/findings/{finding_id}/resolve", response_model=FindingResult)
async def resolve_finding(
    finding_id: str,
    body: FindingActionRequest,
    user: TokenPayload = _auth,
) -> FindingResult:
    """Mark a finding as RESOLVED.

    The user is asserting they have addressed the underlying issue
    outside of CloudGuardIQ. A subsequent scan that re-detects the same
    issue will flip the status back to OPEN automatically.
    """
    settings = get_settings()
    actor = "" if settings.auth_disabled else (user.sub or "")
    return await _mutate_finding_status(
        finding_id, body, user, FindingStatus.RESOLVED,
        extras={
            "resolved_at": datetime.now(timezone.utc),
            "resolved_by": actor,
        },
    )


@app.post("/findings/{finding_id}/snooze", response_model=FindingResult)
async def snooze_finding(
    finding_id: str,
    body: FindingActionRequest,
    user: TokenPayload = _auth,
) -> FindingResult:
    """Snooze a finding for ``body.days`` days (default 7)."""
    days = max(1, min(body.days, 90))
    return await _mutate_finding_status(
        finding_id, body, user, FindingStatus.SNOOZED,
        extras={
            "snoozed_until": datetime.now(timezone.utc) + timedelta(days=days),
        },
    )


@app.post("/findings/{finding_id}/apply", response_model=FindingResult)
async def apply_finding_fix(
    finding_id: str,
    body: FindingActionRequest,
    user: TokenPayload = _auth,
) -> FindingResult:
    """Mark a finding as APPLIED (Self-Heal / terraform fix dispatched).

    This route only stamps the lifecycle field; the actual self-healing
    pipeline is invoked separately by the Self-Heal flow.
    """
    return await _mutate_finding_status(
        finding_id, body, user, FindingStatus.APPLIED,
        extras={"applied_at": datetime.now(timezone.utc)},
    )


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
    if _billing_repo is not None:
        quota = await check_ai_quota(
            tenant_id, billing_repo=_billing_repo, usage_repo=_usage_repo,
        )
        if not quota.allowed:
            raise HTTPException(status_code=402, detail=quota.to_detail())

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
        await record_ai_remediation(tenant_id, usage_repo=_usage_repo)
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








async def _providers_for_scope(
    *,
    user: TokenPayload,
    subscription_id: str,
) -> set | None:
    """Return the set of CloudProvider values that the scoring functions
    should restrict their rule catalogue to.

    * If a specific ``subscription_id`` is supplied we look up the
      SubscriptionRecord and return ``{record.provider}`` so we never
      count rule packs for clouds the caller has not connected.
    * If no subscription is specified (tenant-wide view in dev mode)
      we return ``None`` to keep the legacy "all rules" denominator.
    """
    from cloudguardiq.core.enums import CloudProvider
    settings = get_settings()
    if not subscription_id or settings.auth_disabled:
        return None
    try:
        repo = subscriptions_module._repository  # noqa: SLF001
        if repo is None:
            return None
        tenant_id = get_tenant_id(user)
        record = await repo.get(tenant_id, subscription_id.lower())
        if record is None:
            return None
        provider = getattr(record, "provider", None)
        if isinstance(provider, CloudProvider):
            return {provider}
        if isinstance(provider, str):
            try:
                return {CloudProvider(provider)}
            except ValueError:
                return None
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to resolve provider scope for %s: %s", subscription_id, exc)
    return None


@app.get(
    "/compliance/scorecard",
    response_model=list[ComplianceFrameworkScore],
)
async def get_compliance_scorecard(
    subscription_id: str = Query(default=""),
    from_date: str | None = Query(default=None),
    to_date: str | None = Query(default=None),
    user: TokenPayload = _auth,
) -> list[ComplianceFrameworkScore]:
    """Return per-framework compliance scores for the requested subscription.

    The score for each framework is computed as ``controls_passed /
    controls_total * 100`` where the denominator is the set of controls
    actively evaluated by CloudGuardIQ's rule registry (not the published
    catalogue size). Only OPEN findings contribute to ``controls_failed``.
    Resolved, snoozed, and applied findings are excluded.

    Frameworks with zero evaluated controls return ``score=100`` with
    ``controls_total=0`` so the UI can render a "Not yet evaluated" badge
    without surfacing a misleading red ring.
    """
    repo = get_repo()
    sub_id = ""
    if subscription_id:
        sub_id = await _validate_owned_subscription(user, subscription_id)
        bind_context(subscription_id=sub_id, provider="azure")
    settings = get_settings()
    tenant_id = None if settings.auth_disabled else get_tenant_id(user)

    findings: list[FindingResult] = []
    if repo is not None and sub_id:
        try:
            findings = await repo.get_findings(
                sub_id,
                tenant_id=tenant_id,
                limit=5000,
                from_date=from_date,
                to_date=to_date,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "Compliance scorecard: failed to query findings from Cosmos: %s",
                exc,
            )
            findings = []
    elif settings.auth_disabled and not sub_id:
        # Local/dev mode: surface demo findings so the dashboard isn't blank.
        findings = _demo_findings()

    providers = await _providers_for_scope(user=user, subscription_id=sub_id)
    return compute_compliance_scorecard(findings, providers=providers)


@app.get(
    "/posture/score",
    response_model=PostureScore,
)
async def get_posture_score(
    subscription_id: str = Query(default=""),
    from_date: str | None = Query(default=None),
    to_date: str | None = Query(default=None),
    user: TokenPayload = _auth,
) -> PostureScore:
    """Return the weighted control-pass posture score for the scope.

    Methodology (industry-aligned, matches Microsoft Defender Secure
    Score and AWS Security Hub):

        score = 100 * (sum of severity-weights of passing rules)
                       / (sum of severity-weights of all rules)

    A rule is *passing* when no OPEN finding for that rule_id exists in
    the scope. Severity weights are CRITICAL=10, HIGH=5, MEDIUM=2,
    LOW=1, INFORMATIONAL=0.
    """
    repo = get_repo()
    sub_id = ""
    if subscription_id:
        sub_id = await _validate_owned_subscription(user, subscription_id)
        bind_context(subscription_id=sub_id, provider="azure")
    settings = get_settings()
    tenant_id = None if settings.auth_disabled else get_tenant_id(user)

    findings: list[FindingResult] = []
    if repo is not None and sub_id:
        try:
            findings = await repo.get_findings(
                sub_id,
                tenant_id=tenant_id,
                limit=5000,
                from_date=from_date,
                to_date=to_date,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "Posture score: failed to query findings from Cosmos: %s",
                exc,
            )
            findings = []
    elif settings.auth_disabled and not sub_id:
        findings = _demo_findings()

    providers = await _providers_for_scope(user=user, subscription_id=sub_id)
    return compute_posture_score(findings, providers=providers)


