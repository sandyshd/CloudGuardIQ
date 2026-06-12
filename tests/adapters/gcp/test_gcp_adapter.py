"""Smoke tests for the GCP adapter.

The google client libraries are imported lazily inside the adapter so the
core unit tests stub the scanner methods and verify the asyncio.to_thread
plumbing returns whatever the synchronous collectors yield.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from cloudguardiq.adapters.gcp.adapter import GCPAdapter
from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


def _stub_snapshot(rt: str, name: str) -> ResourceSnapshot:
    return ResourceSnapshot(
        tenant_id="",
        provider=CloudProvider.GCP,
        subscription_id="proj-123",
        resource_group="gcp-global",
        resource_type=rt,
        resource_name=name,
        region="us-central1",
        config={},
        tags={},
        data_tier=DataTier.TIER1_NATIVE,
        captured_at=datetime.now(timezone.utc),
    )


def test_snapshot_factory_stamps_provider_and_tier() -> None:
    """_snapshot tags every result with GCP + TIER1_NATIVE."""
    adapter = GCPAdapter(project_id="proj-123")
    snap = adapter._snapshot(  # noqa: SLF001
        resource_type="google.compute.Instance",
        resource_name="vm-a",
        region="us-central1",
        config={"status": "RUNNING"},
    )
    assert snap.provider is CloudProvider.GCP
    assert snap.subscription_id == "proj-123"
    assert snap.data_tier is DataTier.TIER1_NATIVE
    assert snap.resource_type == "google.compute.Instance"


def test_scan_aggregates_collector_outputs(monkeypatch) -> None:
    """scan() must merge results from every per-resource collector."""
    adapter = GCPAdapter(project_id="proj-123")

    monkeypatch.setattr(
        "cloudguardiq.adapters.gcp.adapter._require_google",
        lambda: None,
    )
    monkeypatch.setattr(
        adapter, "_scan_compute_instances",
        lambda: [_stub_snapshot("google.compute.Instance", "vm-a")],
    )
    monkeypatch.setattr(
        adapter, "_scan_compute_disks",
        lambda: [_stub_snapshot("google.compute.Disk", "d-1")],
    )
    monkeypatch.setattr(
        adapter, "_scan_firewalls",
        lambda: [_stub_snapshot("google.compute.Firewall", "fw-1")],
    )
    monkeypatch.setattr(
        adapter, "_scan_storage_buckets",
        lambda: [_stub_snapshot("google.storage.Bucket", "b-1")],
    )
    monkeypatch.setattr(
        adapter, "_scan_service_accounts",
        lambda: [_stub_snapshot("google.iam.ServiceAccount", "sa@x")],
    )

    snaps = asyncio.run(adapter.scan())
    assert len(snaps) == 5
    assert {s.resource_type for s in snaps} == {
        "google.compute.Instance",
        "google.compute.Disk",
        "google.compute.Firewall",
        "google.storage.Bucket",
        "google.iam.ServiceAccount",
    }


def test_legacy_methods_are_safe_noops() -> None:
    """The Azure-shaped legacy methods must not raise on the GCP adapter."""
    adapter = GCPAdapter(project_id="proj-123")
    assert asyncio.run(adapter.get_resource("nope")) is None
    assert asyncio.run(adapter.get_cost("nope")) == 0.0
    assert asyncio.run(adapter.get_raw_properties("nope")) == {}
    snap = _stub_snapshot("google.compute.Instance", "vm-a")
    assert asyncio.run(adapter.enrich_with_defender([snap])) == [snap]


def test_scan_populates_policy_findings(monkeypatch) -> None:
    adapter = GCPAdapter(project_id="proj-123")

    monkeypatch.setattr(
        "cloudguardiq.adapters.gcp.adapter._require_google",
        lambda: None,
    )
    monkeypatch.setattr(
        adapter, "_scan_compute_instances",
        lambda: [_stub_snapshot("google.compute.Instance", "vm-a")],
    )
    monkeypatch.setattr(adapter, "_scan_compute_disks", lambda: [])
    monkeypatch.setattr(adapter, "_scan_firewalls", lambda: [])
    monkeypatch.setattr(adapter, "_scan_storage_buckets", lambda: [])
    monkeypatch.setattr(adapter, "_scan_service_accounts", lambda: [])

    policy = FindingResult(
        rule_id="GCPPOL-CIS_3_1",
        severity=Severity.HIGH,
        finding_type=FindingType.COMPLIANCE,
    )

    async def _fetch() -> list[FindingResult]:
        return [policy]

    monkeypatch.setattr(adapter._policy_adapter, "fetch_findings", _fetch)

    asyncio.run(adapter.scan())

    assert len(adapter.policy_findings) == 1
    assert adapter.policy_findings[0].rule_id == "GCPPOL-CIS_3_1"
