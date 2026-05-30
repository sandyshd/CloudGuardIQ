"""Tests for FindingResult deterministic id + lifecycle persistence."""

from __future__ import annotations

from typing import Any

import pytest

from cloudguardiq.core.enums import (
    DataTier,
    FindingStatus,
    FindingType,
    Severity,
)
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


def _snap(name: str = "vm-1", sub: str = "sub-1") -> ResourceSnapshot:
    return ResourceSnapshot(
        provider="AZURE",
        subscription_id=sub,
        tenant_id="tenant-x",
        resource_group="rg-1",
        resource_name=name,
        resource_type="Microsoft.Compute/virtualMachines",
        region="eastus",
        data_tier=DataTier.TIER1_NATIVE,
    )


def test_finding_id_is_deterministic_for_same_rule_and_resource() -> None:
    snap = _snap()
    a = FindingResult(
        rule_id="VM-001", severity=Severity.HIGH,
        finding_type=FindingType.SECURITY,
        resource_snapshot=snap, tenant_id="tenant-x",
    )
    b = FindingResult(
        rule_id="VM-001", severity=Severity.HIGH,
        finding_type=FindingType.SECURITY,
        resource_snapshot=snap, tenant_id="tenant-x",
    )
    assert a.finding_id == b.finding_id
    assert len(a.finding_id) == 64  # sha256 hex


def test_finding_id_differs_across_rules() -> None:
    snap = _snap()
    a = FindingResult(rule_id="VM-001", severity=Severity.HIGH,
                      resource_snapshot=snap, tenant_id="tenant-x")
    b = FindingResult(rule_id="VM-002", severity=Severity.HIGH,
                      resource_snapshot=snap, tenant_id="tenant-x")
    assert a.finding_id != b.finding_id


def test_finding_id_differs_across_resources() -> None:
    a = FindingResult(rule_id="VM-001", severity=Severity.HIGH,
                      resource_snapshot=_snap("vm-1"), tenant_id="t")
    b = FindingResult(rule_id="VM-001", severity=Severity.HIGH,
                      resource_snapshot=_snap("vm-2"), tenant_id="t")
    assert a.finding_id != b.finding_id


def test_finding_id_differs_across_tenants() -> None:
    snap = _snap()
    a = FindingResult(rule_id="VM-001", severity=Severity.HIGH,
                      resource_snapshot=snap, tenant_id="tenant-a")
    b = FindingResult(rule_id="VM-001", severity=Severity.HIGH,
                      resource_snapshot=snap, tenant_id="tenant-b")
    assert a.finding_id != b.finding_id


def test_caller_supplied_finding_id_is_honoured() -> None:
    f = FindingResult(
        finding_id="legacy-explicit-id",
        rule_id="VM-001", severity=Severity.HIGH,
        resource_snapshot=_snap(), tenant_id="t",
    )
    assert f.finding_id == "legacy-explicit-id"


def test_finding_without_snapshot_keeps_uuid() -> None:
    # No resource snapshot -> not enough data for stable id; UUID retained
    f = FindingResult(rule_id="VM-001", severity=Severity.HIGH)
    assert len(f.finding_id) == 36  # uuid4 string form


# ---------------------------------------------------------------------------
# Lifecycle merge in CosmosRepository.save_finding
# ---------------------------------------------------------------------------
class _FakeContainer:
    def __init__(self) -> None:
        self.docs: dict[tuple[str, str], dict[str, Any]] = {}

    async def read_item(self, *, item: str, partition_key: str) -> dict[str, Any]:
        if (item, partition_key) not in self.docs:
            raise RuntimeError("not found")
        return dict(self.docs[(item, partition_key)])

    async def upsert_item(self, doc: dict[str, Any]) -> None:
        self.docs[(doc["id"], doc["subscription_id"])] = dict(doc)

    async def query_items(self, query: str, parameters: list[Any] | None = None,
                          partition_key: str | None = None) -> Any:
        for (_id, sub), d in self.docs.items():
            if sub == partition_key and d.get("status") == "OPEN":
                yield dict(d)


class _FakeRepo:
    """Minimal stand-in around CosmosRepository.save_finding.

    We import the real method as an unbound function and call it with a
    duck-typed self, so the behaviour we test is the production code path.
    """

    def __init__(self) -> None:
        self.container = _FakeContainer()

    def _findings_container(self) -> _FakeContainer:
        return self.container


@pytest.mark.asyncio
async def test_save_finding_preserves_resolved_status_on_rescan() -> None:
    from cloudguardiq.core.database import CosmosRepository

    repo = _FakeRepo()
    snap = _snap()
    f = FindingResult(
        rule_id="VM-001", severity=Severity.HIGH,
        resource_snapshot=snap, tenant_id="tenant-x",
    )
    # First scan
    await CosmosRepository.save_finding(repo, f, scan_id="scan-1")  # type: ignore[arg-type]
    # Operator marks RESOLVED out of band
    key = (f.finding_id, snap.subscription_id)
    repo.container.docs[key]["status"] = FindingStatus.RESOLVED.value
    repo.container.docs[key]["resolved_by"] = "operator@x"
    # Second scan re-detects the same issue
    await CosmosRepository.save_finding(repo, f, scan_id="scan-2")  # type: ignore[arg-type]
    saved = repo.container.docs[key]
    assert saved["status"] == FindingStatus.RESOLVED.value
    assert saved["resolved_by"] == "operator@x"
    assert saved["seen_count"] == 2
    assert saved["last_seen_scan_id"] == "scan-2"


@pytest.mark.asyncio
async def test_save_finding_increments_seen_count_and_pins_first_seen() -> None:
    from cloudguardiq.core.database import CosmosRepository

    repo = _FakeRepo()
    snap = _snap()
    f = FindingResult(
        rule_id="VM-001", severity=Severity.HIGH,
        resource_snapshot=snap, tenant_id="tenant-x",
    )
    await CosmosRepository.save_finding(repo, f, scan_id="scan-1")  # type: ignore[arg-type]
    first_seen = repo.container.docs[(f.finding_id, snap.subscription_id)]["first_seen_at"]
    await CosmosRepository.save_finding(repo, f, scan_id="scan-2")  # type: ignore[arg-type]
    saved = repo.container.docs[(f.finding_id, snap.subscription_id)]
    assert saved["first_seen_at"] == first_seen   # pinned
    assert saved["seen_count"] == 2


@pytest.mark.asyncio
async def test_mark_unseen_findings_resolved() -> None:
    from cloudguardiq.core.database import CosmosRepository

    repo = _FakeRepo()
    snap = _snap()
    a = FindingResult(rule_id="VM-001", severity=Severity.HIGH,
                      resource_snapshot=snap, tenant_id="tenant-x")
    b = FindingResult(rule_id="VM-002", severity=Severity.HIGH,
                      resource_snapshot=snap, tenant_id="tenant-x")
    await CosmosRepository.save_finding(repo, a, scan_id="s1")  # type: ignore[arg-type]
    await CosmosRepository.save_finding(repo, b, scan_id="s1")  # type: ignore[arg-type]
    # Next scan re-detects only `a`
    resolved = await CosmosRepository.mark_unseen_findings_resolved(
        repo, snap.subscription_id, {a.finding_id}, "s2",  # type: ignore[arg-type]
        tenant_id="tenant-x",
    )
    assert resolved == 1
    saved_b = repo.container.docs[(b.finding_id, snap.subscription_id)]
    assert saved_b["status"] == "RESOLVED"
    assert saved_b["resolved_by"] == "auto:scan"
    assert saved_b["auto_resolved_scan_id"] == "s2"


class _FakeFindingsReadContainer:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = [dict(r) for r in rows]

    async def query_items(
        self,
        query: str,
        parameters: list[Any] | None = None,
        partition_key: str | None = None,
    ) -> Any:
        for row in self.rows:
            if partition_key and row.get("subscription_id") != partition_key:
                continue
            yield dict(row)


class _FakeFindingsReadRepo:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.container = _FakeFindingsReadContainer(rows)

    def _findings_container(self) -> _FakeFindingsReadContainer:
        return self.container


@pytest.mark.asyncio
async def test_get_findings_normalises_legacy_null_string_fields() -> None:
    from cloudguardiq.core.database import CosmosRepository

    snap = _snap()
    finding = FindingResult(
        rule_id="VM-001",
        severity=Severity.HIGH,
        resource_snapshot=snap,
        tenant_id="tenant-x",
    )
    doc = finding.model_dump(mode="json")
    doc["id"] = finding.finding_id
    doc["subscription_id"] = snap.subscription_id
    doc["resolved_by"] = None
    doc["last_seen_scan_id"] = None

    repo = _FakeFindingsReadRepo([doc])
    rows = await CosmosRepository.get_findings(
        repo,  # type: ignore[arg-type]
        subscription_id=snap.subscription_id,
        tenant_id="tenant-x",
        limit=50,
    )

    assert len(rows) == 1
    assert rows[0].resolved_by == ""
    assert rows[0].last_seen_scan_id == ""


class _FakeSnapshotContainer:
    def __init__(self) -> None:
        self.docs: list[dict[str, Any]] = []

    async def upsert_item(self, doc: dict[str, Any]) -> None:
        self.docs.append(dict(doc))


class _FakeSnapshotRepo:
    def __init__(self) -> None:
        self.container = _FakeSnapshotContainer()

    def _snapshots_container(self) -> _FakeSnapshotContainer:
        return self.container


@pytest.mark.asyncio
async def test_save_snapshot_uses_cosmos_safe_id_for_slashy_resource_id() -> None:
    from cloudguardiq.core.database import CosmosRepository

    repo = _FakeSnapshotRepo()
    snap = ResourceSnapshot(
        id=(
            "azure/storageaccounts/sub-1/rg-1/"
            "name-with/slash"
        ),
        provider="AZURE",
        subscription_id="sub-1",
        tenant_id="tenant-x",
        resource_group="rg-1",
        resource_name="name-with/slash",
        resource_type="Microsoft.Storage/storageAccounts",
        region="eastus",
        data_tier=DataTier.TIER1_NATIVE,
    )

    returned = await CosmosRepository.save_snapshot(repo, snap)  # type: ignore[arg-type]

    assert returned == snap.id
    assert len(repo.container.docs) == 1
    saved = repo.container.docs[0]
    assert saved["resource_id"] == snap.id
    assert saved["id"] != snap.id
    assert len(saved["id"]) == 64
