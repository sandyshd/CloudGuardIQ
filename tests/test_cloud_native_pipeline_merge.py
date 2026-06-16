"""Tests for merging AWS/GCP cloud-native findings into the pipeline."""

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

SUB = "acct-1"


def _snap(name: str, rg: str = "aws-global") -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id=SUB,
        resource_group=rg,
        resource_type="AwsS3Bucket",
        resource_name=name,
        region="us-east-1",
        provider=CloudProvider.AWS,
        data_tier=DataTier.TIER1_NATIVE,
        config={},
    )


def _native(rule_id: str, snap: ResourceSnapshot) -> FindingResult:
    return FindingResult(
        rule_id=rule_id,
        rule_name=rule_id,
        severity=Severity.HIGH,
        finding_type=FindingType.SECURITY,
        description="native",
        resource_snapshot=snap,
    )


def _cloud_native(
    rule_id: str, snap: ResourceSnapshot, *, overlap: str = "",
) -> FindingResult:
    rkey = f"{snap.resource_group.lower()}/{snap.resource_name.lower()}"
    return FindingResult(
        finding_id=AdapterBase.build_finding_id(rule_id, snap.id),
        rule_id=rule_id,
        rule_name=rule_id,
        severity=Severity.MEDIUM,
        finding_type=FindingType.SECURITY,
        description="cloud-native",
        resource_snapshot=snap,
        evidence={"native_rule_overlap": overlap, "resource_key": rkey},
    )


def _build(attr: str, snapshots, native, cloud_native):
    adapter = MagicMock()
    adapter.scan = AsyncMock(return_value=snapshots)
    adapter.policy_findings = []
    # Ensure the *other* source attrs are absent so only `attr` is merged.
    for name in ("defender_findings", "securityhub_findings", "scc_findings"):
        setattr(adapter, name, cloud_native if name == attr else [])

    policy = MagicMock()
    policy.evaluate = MagicMock(return_value=list(native))
    policy.covered_resource_types = MagicMock(return_value=frozenset())

    db = MagicMock()
    db.save_finding = AsyncMock()
    db.save_scan_result = AsyncMock()
    db.mark_unseen_findings_resolved = AsyncMock()

    pipeline = ScanPipeline(
        adapter=adapter, policy_engine=policy, ai_engine=None, db=db,
    )
    return pipeline, db


@pytest.mark.asyncio
@pytest.mark.parametrize("attr", ["securityhub_findings", "scc_findings"])
async def test_cloud_native_findings_merged_and_scored(attr: str) -> None:
    snap = _snap("bucket-a")
    src = [_cloud_native("SECHUB-x", _snap("other-res", "aws-global"))]
    pipeline, db = _build(attr, [snap], native=[], cloud_native=src)

    result = await pipeline.run(SUB, tenant_id="t1")

    assert result.findings_count == 1
    saved = [c.args[0] for c in db.save_finding.await_args_list]
    assert saved[0].rule_id == "SECHUB-x"
    assert saved[0].priority_score > 0
    assert saved[0].tenant_id == "t1"


@pytest.mark.asyncio
@pytest.mark.parametrize("attr", ["securityhub_findings", "scc_findings"])
async def test_overlap_collapses_to_native(attr: str) -> None:
    snap = _snap("bucket-a")
    native = [_native("AWS-S3-002", snap)]
    src = [_cloud_native("SECHUB-x", snap, overlap="AWS-S3-002")]
    pipeline, db = _build(attr, [snap], native=native, cloud_native=src)

    result = await pipeline.run(SUB, tenant_id="t1")

    assert result.findings_count == 1
    saved = [c.args[0] for c in db.save_finding.await_args_list]
    assert saved[0].rule_id == "AWS-S3-002"
    assert all(not f.rule_id.startswith("SECHUB-") for f in saved)


@pytest.mark.asyncio
@pytest.mark.parametrize("attr", ["securityhub_findings", "scc_findings"])
async def test_non_overlapping_kept(attr: str) -> None:
    snap = _snap("bucket-a")
    native = [_native("AWS-S3-001", snap)]
    src = [_cloud_native("SECHUB-x", snap, overlap="AWS-S3-009")]
    pipeline, db = _build(attr, [snap], native=native, cloud_native=src)

    result = await pipeline.run(SUB, tenant_id="t1")

    assert result.findings_count == 2
    rule_ids = {c.args[0].rule_id for c in db.save_finding.await_args_list}
    assert rule_ids == {"AWS-S3-001", "SECHUB-x"}
