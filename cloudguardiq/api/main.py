"""CloudGuardIQ — FastAPI application."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException

from cloudguardiq.adapters.azure_adapter import AzureAdapter
from cloudguardiq.adapters.native_scanner import NativeScanner
from cloudguardiq.adapters.rules.compute import VMNoEncryptionRule, VMUnmanagedDisksRule
from cloudguardiq.adapters.rules.finops import UnattachedDiskRule, UnderutilizedVMRule
from cloudguardiq.adapters.rules.keyvault import KeyVaultPurgeProtectionRule, KeyVaultSoftDeleteRule
from cloudguardiq.adapters.rules.network import NSGOpenRDPRule, NSGOpenSSHRule
from cloudguardiq.adapters.rules.storage import StorageHttpsOnlyRule, StoragePublicAccessRule
from cloudguardiq.core.models import FindingResult, ScanRequest, ScanResponse
from cloudguardiq.policy.engine import PolicyEngine

logger = logging.getLogger(__name__)

app = FastAPI(title="CloudGuardIQ", version="0.1.0")


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
        engine.register_rule(rule.evaluate)
    return engine


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan_subscription(request: ScanRequest) -> ScanResponse:
    """Scan an Azure subscription for security and cost findings."""
    adapter = AzureAdapter()
    scanner = _build_scanner()
    engine = _build_policy_engine(scanner)

    try:
        snapshots = await adapter.list_resources(request.subscription_id)
    except Exception as exc:
        logger.error("Failed to list resources: %s", exc)
        raise HTTPException(status_code=502, detail="Failed to list Azure resources") from exc

    # Enrich with Defender (best-effort)
    snapshots = await adapter.enrich_with_defender(snapshots)

    findings: list[FindingResult] = engine.evaluate(snapshots)

    return ScanResponse(
        subscription_id=request.subscription_id,
        snapshots_count=len(snapshots),
        findings_count=len(findings),
        findings=findings,
    )


@app.get("/findings/{finding_id}")
async def get_finding(finding_id: str) -> dict[str, str]:
    """Get a single finding by ID (stub)."""
    return {"finding_id": finding_id, "status": "stub"}
