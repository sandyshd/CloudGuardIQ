"""Tests for Defender for Cloud assessment ingestion as first-class findings."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

import cloudguardiq.adapters.azure.adapter as adapter_module
from cloudguardiq.adapters.azure.adapter import AzureAdapter
from cloudguardiq.adapters.base import CapabilityFlags
from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import ResourceSnapshot

SUB = "sub-123"


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


def _assessment(
    *,
    name: str,
    display_name: str,
    status: str,
    severity: str,
    arm_id: str,
    description: str = "desc",
    categories: list[str] | None = None,
) -> SimpleNamespace:
    """Build a fake Defender assessment resembling the SDK model."""
    return SimpleNamespace(
        name=name,
        display_name=display_name,
        id=f"{arm_id}/providers/Microsoft.Security/assessments/{name}",
        status=SimpleNamespace(code=status, description=description),
        resource_details=SimpleNamespace(id=arm_id),
        metadata=SimpleNamespace(
            severity=severity,
            description=description,
            categories=categories or [],
            remediation_description="do the thing",
        ),
    )


class _FakeAssessments:
    def __init__(self, items: list[Any], raises: bool = False) -> None:
        self._items = items
        self._raises = raises

    async def list(self, scope: str) -> Any:  # noqa: A003 - SDK name
        if self._raises:
            raise RuntimeError("defender boom")
        for item in self._items:
            yield item


class _FakeAlerts:
    def __init__(self, items: list[Any] | None = None) -> None:
        self._items = items or []

    async def list(self) -> Any:  # noqa: A003 - SDK name
        for item in self._items:
            yield item


class _FakeSecurityCenter:
    def __init__(
        self, assessments: list[Any], raises: bool = False,
    ) -> None:
        self.assessments = _FakeAssessments(assessments, raises=raises)
        self.alerts = _FakeAlerts()
        self.closed = False

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def mock_db() -> MagicMock:
    db = MagicMock()
    db.get_capability_flags = AsyncMock(return_value=None)
    db.save_capability_flags = AsyncMock()
    return db


@pytest.fixture
def adapter(mock_db: MagicMock) -> AzureAdapter:
    return AzureAdapter(
        credential=MagicMock(), subscription_id=SUB, db=mock_db,
    )


def _arm(rg: str, name: str, rtype: str = "Microsoft.Storage/storageAccounts") -> str:
    return (
        f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/{rtype}/{name}"
    )


def _set_flags(adapter: AzureAdapter, *, tier2: bool, tier3: bool = False) -> None:
    adapter._capability_detector.detect = AsyncMock(  # type: ignore[method-assign]
        return_value=CapabilityFlags(
            tier1_available=True,
            tier2_available=tier2,
            tier3_available=tier3,
        ),
    )


@pytest.mark.asyncio
async def test_only_unhealthy_become_findings_covered_and_uncovered(
    adapter: AzureAdapter,
) -> None:
    """Unhealthy assessments -> findings; uncovered type still emitted."""
    _set_flags(adapter, tier2=True)
    covered = _snap("stg1")
    assessments = [
        _assessment(
            name="a-healthy", display_name="Healthy one", status="Healthy",
            severity="High", arm_id=_arm("rg1", "stg1"),
        ),
        _assessment(
            name="a-covered", display_name="TLS weak", status="Unhealthy",
            severity="Medium", arm_id=_arm("rg1", "stg1"),
        ),
        _assessment(
            name="a-uncovered", display_name="ACR admin enabled",
            status="Unhealthy", severity="High",
            arm_id=_arm("rg9", "myregistry", "Microsoft.ContainerRegistry/registries"),
        ),
    ]
    fake = _FakeSecurityCenter(assessments)
    adapter._security_center_client = MagicMock(return_value=fake)  # type: ignore[method-assign]

    findings = await adapter.fetch_defender_findings([covered])

    names = {f.rule_name for f in findings}
    assert names == {"TLS weak", "ACR admin enabled"}  # no Healthy
    assert all(f.finding_type == FindingType.SECURITY for f in findings)
    assert all(f.priority_score > 0 for f in findings)
    assert fake.closed is True

    uncovered = next(f for f in findings if f.rule_name == "ACR admin enabled")
    assert uncovered.evidence["arm_resource_id"] == _arm(
        "rg9", "myregistry", "Microsoft.ContainerRegistry/registries",
    )
    assert uncovered.resource_snapshot is not None
    assert uncovered.resource_snapshot.resource_name == "myregistry"

    # Covered assessment stamps the matched snapshot's tier.
    assert covered.data_tier == DataTier.TIER2_FREE_CSPM


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Low", Severity.LOW),
        ("Medium", Severity.MEDIUM),
        ("High", Severity.HIGH),
        ("weird", Severity.MEDIUM),
    ],
)
async def test_severity_mapping(
    adapter: AzureAdapter, raw: str, expected: Severity,
) -> None:
    _set_flags(adapter, tier2=True)
    a = _assessment(
        name="a1", display_name="x", status="Unhealthy", severity=raw,
        arm_id=_arm("rg1", "stg1"),
    )
    adapter._security_center_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeSecurityCenter([a]),
    )
    findings = await adapter.fetch_defender_findings([_snap("stg1")])
    assert findings[0].severity == expected


@pytest.mark.asyncio
async def test_defender_failure_returns_empty(adapter: AzureAdapter) -> None:
    """A raising Defender call degrades to [] without propagating."""
    _set_flags(adapter, tier2=True)
    adapter._security_center_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeSecurityCenter([], raises=True),
    )
    findings = await adapter.fetch_defender_findings([_snap("stg1")])
    assert findings == []


@pytest.mark.asyncio
async def test_tier2_unavailable_makes_no_calls(adapter: AzureAdapter) -> None:
    _set_flags(adapter, tier2=False)
    client_factory = MagicMock()
    adapter._security_center_client = client_factory  # type: ignore[method-assign]
    findings = await adapter.fetch_defender_findings([_snap("stg1")])
    assert findings == []
    client_factory.assert_not_called()


@pytest.mark.asyncio
async def test_deterministic_finding_id_stable(adapter: AzureAdapter) -> None:
    _set_flags(adapter, tier2=True)
    a = _assessment(
        name="a1", display_name="x", status="Unhealthy", severity="High",
        arm_id=_arm("rg1", "stg1"),
    )
    adapter._security_center_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeSecurityCenter([a]),
    )
    first = await adapter.fetch_defender_findings([_snap("stg1")])
    adapter._security_center_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeSecurityCenter([a]),
    )
    second = await adapter.fetch_defender_findings([_snap("stg1")])
    assert first[0].finding_id == second[0].finding_id


@pytest.mark.asyncio
async def test_overlap_marks_native_rule_for_dedup(
    adapter: AzureAdapter, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mapped assessment records the native rule it overlaps."""
    _set_flags(adapter, tier2=True)
    monkeypatch.setitem(
        adapter_module.DEFENDER_TO_NATIVE_RULE, "a-https", "STOR-002",
    )
    a = _assessment(
        name="a-https", display_name="Secure transfer", status="Unhealthy",
        severity="High", arm_id=_arm("rg1", "stg1"),
    )
    adapter._security_center_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeSecurityCenter([a]),
    )
    findings = await adapter.fetch_defender_findings([_snap("stg1")])
    assert findings[0].evidence["native_rule_overlap"] == "STOR-002"
    assert findings[0].evidence["resource_key"] == "rg1/stg1"
