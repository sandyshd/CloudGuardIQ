"""Tests for GCP Security Command Center finding ingestion."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

import cloudguardiq.adapters.gcp.adapter as adapter_module
from cloudguardiq.adapters.base import CapabilityFlags
from cloudguardiq.adapters.gcp.adapter import GCPAdapter
from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import ResourceSnapshot

PROJECT = "my-project"


def _snap(name: str, rtype: str = "compute.googleapis.com/Instance") -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id=PROJECT,
        resource_group="gcp-global",
        resource_type=rtype,
        resource_name=name,
        region="us-central1",
        provider=CloudProvider.GCP,
        data_tier=DataTier.TIER1_NATIVE,
        config={},
    )


def _res_name(kind: str, name: str) -> str:
    return f"//compute.googleapis.com/projects/{PROJECT}/zones/us-central1-a/{kind}/{name}"


def _scc_row(
    *,
    name: str,
    category: str,
    severity: str,
    resource_name: str,
    state: str = "ACTIVE",
    description: str = "desc",
) -> dict[str, Any]:
    return {
        "name": name,
        "category": category,
        "severity": severity,
        "state": state,
        "description": description,
        "resource_name": resource_name,
        "event_time": "2026-05-01T00:00:00Z",
    }


class _FakeScc:
    def __init__(self, rows: list[dict[str, Any]], raises: bool = False) -> None:
        self._rows = rows
        self._raises = raises
        self.calls = 0

    def list_findings(self, request: Any) -> Any:
        self.calls += 1
        if self._raises:
            raise RuntimeError("scc boom")
        yield from self._rows


@pytest.fixture
def adapter() -> GCPAdapter:
    return GCPAdapter(project_id=PROJECT, credentials=MagicMock())


def _flags(*, tier2: bool = True, tier3: bool = False) -> CapabilityFlags:
    return CapabilityFlags(
        tier1_available=True, tier2_available=tier2, tier3_available=tier3,
    )


@pytest.mark.asyncio
async def test_active_findings_become_findings_covered_and_uncovered(
    adapter: GCPAdapter,
) -> None:
    covered = _snap("vm-a")
    rows = [
        _scc_row(
            name="organizations/o/sources/s/findings/inactive",
            category="OLD", severity="HIGH",
            resource_name=_res_name("instances", "vm-a"), state="INACTIVE",
        ),
        _scc_row(
            name="organizations/o/sources/s/findings/a1",
            category="PUBLIC_IP_ADDRESS", severity="MEDIUM",
            resource_name=_res_name("instances", "vm-a"),
        ),
        _scc_row(
            name="organizations/o/sources/s/findings/a2",
            category="OPEN_FIREWALL", severity="CRITICAL",
            resource_name=_res_name("firewalls", "fw-open"),
        ),
    ]
    fake = _FakeScc(rows)
    adapter._scc_security_client = MagicMock(return_value=fake)  # type: ignore[method-assign]

    out = await adapter.fetch_scc_findings([covered], flags=_flags())

    cats = {f.rule_name for f in out}
    assert cats == {"PUBLIC_IP_ADDRESS", "OPEN_FIREWALL"}
    assert all(f.finding_type == FindingType.SECURITY for f in out)
    assert all(f.priority_score > 0 for f in out)

    uncovered = next(f for f in out if f.rule_name == "OPEN_FIREWALL")
    assert uncovered.evidence["resource_name"] == _res_name("firewalls", "fw-open")
    assert uncovered.resource_snapshot is not None
    assert uncovered.resource_snapshot.resource_name == "fw-open"

    assert covered.data_tier == DataTier.TIER2_ENRICHED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("MEDIUM", Severity.MEDIUM),
        ("LOW", Severity.LOW),
        ("INFO", Severity.INFORMATIONAL),
        ("weird", Severity.MEDIUM),
    ],
)
async def test_severity_mapping(
    adapter: GCPAdapter, label: str, expected: Severity,
) -> None:
    row = _scc_row(
        name="organizations/o/sources/s/findings/a1", category="X",
        severity=label, resource_name=_res_name("instances", "vm-a"),
    )
    adapter._scc_security_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeScc([row]),
    )
    out = await adapter.fetch_scc_findings([_snap("vm-a")], flags=_flags())
    assert out[0].severity == expected


@pytest.mark.asyncio
async def test_scc_failure_returns_empty(adapter: GCPAdapter) -> None:
    adapter._scc_security_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeScc([], raises=True),
    )
    out = await adapter.fetch_scc_findings([_snap("vm-a")], flags=_flags())
    assert out == []


@pytest.mark.asyncio
async def test_tier2_and_tier3_unavailable_makes_no_calls(adapter: GCPAdapter) -> None:
    client_factory = MagicMock()
    adapter._scc_security_client = client_factory  # type: ignore[method-assign]
    out = await adapter.fetch_scc_findings(
        [_snap("vm-a")], flags=_flags(tier2=False, tier3=False),
    )
    assert out == []
    client_factory.assert_not_called()


@pytest.mark.asyncio
async def test_tier3_only_still_ingests(adapter: GCPAdapter) -> None:
    row = _scc_row(
        name="organizations/o/sources/s/findings/a1", category="X",
        severity="HIGH", resource_name=_res_name("instances", "vm-a"),
    )
    adapter._scc_security_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeScc([row]),
    )
    out = await adapter.fetch_scc_findings(
        [_snap("vm-a")], flags=_flags(tier2=False, tier3=True),
    )
    assert len(out) == 1


@pytest.mark.asyncio
async def test_deterministic_finding_id_stable(adapter: GCPAdapter) -> None:
    row = _scc_row(
        name="organizations/o/sources/s/findings/a1", category="X",
        severity="HIGH", resource_name=_res_name("instances", "vm-a"),
    )
    adapter._scc_security_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeScc([row]),
    )
    first = await adapter.fetch_scc_findings([_snap("vm-a")], flags=_flags())
    adapter._scc_security_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeScc([row]),
    )
    second = await adapter.fetch_scc_findings([_snap("vm-a")], flags=_flags())
    assert first[0].finding_id == second[0].finding_id


@pytest.mark.asyncio
async def test_overlap_marks_native_rule_for_dedup(
    adapter: GCPAdapter, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        adapter_module.SCC_TO_NATIVE_RULE, "PUBLIC_IP_ADDRESS", "GCP-VM-003",
    )
    row = _scc_row(
        name="organizations/o/sources/s/findings/a1",
        category="PUBLIC_IP_ADDRESS", severity="HIGH",
        resource_name=_res_name("instances", "vm-a"),
    )
    adapter._scc_security_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeScc([row]),
    )
    out = await adapter.fetch_scc_findings([_snap("vm-a")], flags=_flags())
    assert out[0].evidence["native_rule_overlap"] == "GCP-VM-003"
    assert out[0].evidence["resource_key"] == "gcp-global/vm-a"
