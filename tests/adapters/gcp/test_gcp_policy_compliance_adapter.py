"""Tests for GCPPolicyComplianceAdapter."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from cloudguardiq.adapters.gcp.gcp_policy_compliance_adapter import (
    FRAMEWORK_POSTURES,
    GCPPolicyComplianceAdapter,
)
from cloudguardiq.core.enums import DataTier, FindingType, Severity

PROJECT_ID = "proj-12345"
CIS_FAMILY = FRAMEWORK_POSTURES["CIS_AZURE"]
NIST_FAMILY = FRAMEWORK_POSTURES["NIST_800_53"]


def _finding_row(
    *,
    resource_name: str = "projects/proj-12345/buckets/bucket-a",
    category: str = "cis.3.1",
    event_time: str = "2026-05-01T00:00:00Z",
) -> dict:
    return {
        "name": "organizations/123/sources/1/findings/f-1",
        "category": category,
        "description": "Control failed",
        "severity": "HIGH",
        "event_time": event_time,
        "resource_name": resource_name,
        "source_properties": {
            "resourceType": "google.storage.Bucket",
        },
        "location": "us-central1",
    }


@pytest.fixture
def adapter() -> GCPPolicyComplianceAdapter:
    return GCPPolicyComplianceAdapter(
        project_id=PROJECT_ID,
        credentials=MagicMock(),
        postures=[CIS_FAMILY, NIST_FAMILY],
    )


@pytest.mark.asyncio
async def test_fetch_findings_returns_empty_when_no_posture_enabled(
    adapter: GCPPolicyComplianceAdapter,
) -> None:
    adapter._list_enabled_postures = AsyncMock(return_value=set())  # type: ignore[attr-defined]
    assert await adapter.fetch_findings() == []


@pytest.mark.asyncio
async def test_fetch_findings_skips_unenabled_posture(
    adapter: GCPPolicyComplianceAdapter,
) -> None:
    adapter._list_enabled_postures = AsyncMock(return_value={NIST_FAMILY})  # type: ignore[attr-defined]
    query_spy = AsyncMock(return_value=[])  # type: ignore[attr-defined]
    adapter._query_non_compliant_findings = query_spy  # type: ignore[assignment]

    await adapter.fetch_findings()

    query_spy.assert_awaited_once_with(NIST_FAMILY)


@pytest.mark.asyncio
async def test_dedup_by_resource_and_control_keeps_latest(
    adapter: GCPPolicyComplianceAdapter,
) -> None:
    older = _finding_row(event_time="2026-01-01T00:00:00Z")
    newer = _finding_row(event_time="2026-02-01T00:00:00Z")

    adapter._list_enabled_postures = AsyncMock(return_value={CIS_FAMILY})  # type: ignore[attr-defined]
    adapter._query_non_compliant_findings = AsyncMock(return_value=[older, newer])  # type: ignore[attr-defined]

    findings = await adapter.fetch_findings()

    assert len(findings) == 1
    assert findings[0].evidence["event_time"] == "2026-02-01T00:00:00Z"


def test_to_finding_maps_all_fields(adapter: GCPPolicyComplianceAdapter) -> None:
    finding = adapter._to_finding(_finding_row(), CIS_FAMILY)

    assert finding is not None
    assert finding.rule_id.startswith("GCPPOL-")
    assert finding.rule_name == "cis.3.1"
    assert finding.severity == Severity.HIGH
    assert finding.finding_type == FindingType.COMPLIANCE
    assert finding.compliance_frameworks == ["CIS_AZURE:cis.3.1"]
    assert finding.resource_snapshot is not None
    assert finding.resource_snapshot.data_tier == DataTier.TIER1_NATIVE
    assert finding.resource_snapshot.provider.value == "GCP"


def test_to_finding_returns_none_when_required_fields_missing(
    adapter: GCPPolicyComplianceAdapter,
) -> None:
    row = _finding_row()
    row["resource_name"] = ""
    assert adapter._to_finding(row, CIS_FAMILY) is None


def test_to_finding_is_deterministic(adapter: GCPPolicyComplianceAdapter) -> None:
    first = adapter._to_finding(_finding_row(), CIS_FAMILY)
    second = adapter._to_finding(_finding_row(), CIS_FAMILY)
    assert first is not None and second is not None
    assert first.finding_id == second.finding_id


@pytest.mark.asyncio
async def test_validate_connection_true(adapter: GCPPolicyComplianceAdapter) -> None:
    client = MagicMock()
    client.list_findings.return_value = []
    adapter._scc_client = lambda: client  # type: ignore[method-assign]
    assert await adapter.validate_connection() is True


@pytest.mark.asyncio
async def test_validate_connection_false_on_error(adapter: GCPPolicyComplianceAdapter) -> None:
    client = MagicMock()
    client.list_findings.side_effect = RuntimeError("boom")
    adapter._scc_client = lambda: client  # type: ignore[method-assign]
    assert await adapter.validate_connection() is False


@pytest.mark.asyncio
async def test_scan_returns_empty_list(adapter: GCPPolicyComplianceAdapter) -> None:
    assert await adapter.scan() == []


@pytest.mark.asyncio
async def test_get_api_contract_returns_schema(adapter: GCPPolicyComplianceAdapter) -> None:
    adapter._query_non_compliant_findings = AsyncMock(return_value=[_finding_row()])  # type: ignore[attr-defined]
    contract = await adapter.get_api_contract()
    assert contract["provider"] == "gcp"
    assert contract["endpoint"] == "scc.list_findings"
    assert "category" in contract["schema"]


