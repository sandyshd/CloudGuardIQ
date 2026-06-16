"""Tests for merging Defender findings into the scan pipeline output."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from cloudguardiq.adapters.base import AdapterBase
from cloudguardiq.core.enums import (
    CloudProvider,
    DataTier,
    FindingType,
    Severity,
)
from cloudguardiq.core.models import FindingResult, ResourceSnapshot
from cloudguardiq.pipeline.scan_pipeline import ScanPipeline

SUB = "sub-1"


def _snap(name: str, rg: str = "rg1") -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id=SUB,
        resource_group=rg,
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name=name,
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={},
    )


def _native_finding(rule_id: str, snap: ResourceSnapshot) -> FindingResult:
    return FindingResult(
        rule_id=rule_id,
        rule_name=rule_id,
        severity=Severity.HIGH,
        finding_type=FindingType.SECURITY,
        description="native",
        resource_snapshot=snap,
    )


def _defender_finding(
    name: str,
    snap: ResourceSnapshot,
    *,
    overlap: str = "",
) -> FindingResult:
    rule_id = f"DEFENDER-{name}"
    rkey = f"{snap.resource_group.lower()}/{snap.resource_name.lower()}"
    return FindingResult(
        finding_id=AdapterBase.build_finding_id(rule_id, snap.id),
        rule_id=rule_id,
        rule_name=name,
        severity=Severity.MEDIUM,
        finding_type=FindingType.SECURITY,
        description="defender",
        resource_snapshot=snap,
        evidence={"native_rule_overlap": overlap, "resource_key": rkey},
    )


def _build_pipeline(
    snapshots: list[ResourceSnapshot],
    native: list[FindingResult],
    defender: list[FindingResult],
) -> tuple[ScanPipeline, MagicMock]:
    adapter = MagicMock()
    adapter.scan = AsyncMock(return_value=snapshots)
    adapter.policy_findings = []
    adapter.defender_findings = defender

    policy = MagicMock()
    policy.evaluate = MagicMock(return_value=list(native))
    policy.covered_resource_types = MagicMock(return_value=frozenset())

    db = MagicMock()
    db.save_finding = AsyncMock()
    db.save_scan_result = AsyncMock()
    db.mark_unseen_findings_resolved = AsyncMock()

    pipeline = ScanPipeline(
        adapter=adapter,
        policy_engine=policy,
        ai_engine=None,
        db=db,
    )
    return pipeline, db


@pytest.mark.asyncio
async def test_defender_findings_merged_and_scored() -> None:
    """Defender findings reach ScanResult with priority_score computed."""
    snap = _snap("stg1")
    defender = [_defender_finding("a-uncovered", _snap("acr1", "rg9"))]
    pipeline, db = _build_pipeline([snap], native=[], defender=defender)

    result = await pipeline.run(SUB, tenant_id="t1")

    assert result.findings_count == 1
    saved = [c.args[0] for c in db.save_finding.await_args_list]
    assert saved[0].rule_id == "DEFENDER-a-uncovered"
    assert saved[0].priority_score > 0
    assert saved[0].tenant_id == "t1"


@pytest.mark.asyncio
async def test_native_and_defender_duplicate_collapses_to_native() -> None:
    """When a Defender assessment overlaps a native rule, native wins."""
    snap = _snap("stg1")
    native = [_native_finding("STOR-002", snap)]
    defender = [_defender_finding("a-https", snap, overlap="STOR-002")]
    pipeline, db = _build_pipeline([snap], native=native, defender=defender)

    result = await pipeline.run(SUB, tenant_id="t1")

    assert result.findings_count == 1
    saved = [c.args[0] for c in db.save_finding.await_args_list]
    assert saved[0].rule_id == "STOR-002"  # native preferred
    assert all(not f.rule_id.startswith("DEFENDER-") for f in saved)


@pytest.mark.asyncio
async def test_defender_only_finding_kept_when_no_native_overlap() -> None:
    """Defender findings for uncovered types are never dropped."""
    snap = _snap("stg1")
    native = [_native_finding("STOR-001", snap)]
    # Overlap points at a rule that did NOT fire natively -> keep defender.
    defender = [_defender_finding("a-other", snap, overlap="STOR-009")]
    pipeline, db = _build_pipeline([snap], native=native, defender=defender)

    result = await pipeline.run(SUB, tenant_id="t1")

    assert result.findings_count == 2
    rule_ids = {c.args[0].rule_id for c in db.save_finding.await_args_list}
    assert rule_ids == {"STOR-001", "DEFENDER-a-other"}
