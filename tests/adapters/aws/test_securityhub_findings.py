"""Tests for AWS Security Hub finding ingestion as first-class findings."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

import cloudguardiq.adapters.aws.adapter as adapter_module
from cloudguardiq.adapters.aws.adapter import AWSAdapter
from cloudguardiq.adapters.base import CapabilityFlags
from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import ResourceSnapshot

ACCOUNT = "111122223333"


def _snap(name: str, rtype: str = "AwsS3Bucket") -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id=ACCOUNT,
        resource_group="aws-global",
        resource_type=rtype,
        resource_name=name,
        region="us-east-1",
        provider=CloudProvider.AWS,
        data_tier=DataTier.TIER1_NATIVE,
        config={},
    )


def _asff(
    *,
    finding_id: str,
    title: str,
    label: str,
    arn: str,
    rtype: str = "AwsS3Bucket",
    record_state: str = "ACTIVE",
    standards: list[str] | None = None,
    description: str = "desc",
) -> dict[str, Any]:
    return {
        "Id": finding_id,
        "Title": title,
        "Description": description,
        "Severity": {"Label": label},
        "RecordState": record_state,
        "Resources": [{"Id": arn, "Type": rtype}],
        "Compliance": {
            "AssociatedStandards": [
                {"StandardsId": s} for s in (standards or [])
            ],
        },
    }


class _FakePaginator:
    def __init__(self, pages: list[dict[str, Any]], raises: bool = False) -> None:
        self._pages = pages
        self._raises = raises

    def paginate(self, **kwargs: Any) -> Any:
        if self._raises:
            raise RuntimeError("securityhub boom")
        yield from self._pages


class _FakeSecurityHub:
    def __init__(self, findings: list[dict[str, Any]], raises: bool = False) -> None:
        self._pages = [{"Findings": findings}]
        self._raises = raises
        self.calls = 0

    def get_paginator(self, name: str) -> _FakePaginator:
        self.calls += 1
        assert name == "get_findings"
        return _FakePaginator(self._pages, raises=self._raises)


@pytest.fixture
def adapter() -> AWSAdapter:
    return AWSAdapter(account_id=ACCOUNT, region="us-east-1", session=MagicMock())


def _arn(service: str, name: str) -> str:
    if service == "s3":
        return f"arn:aws:s3:::{name}"
    return f"arn:aws:{service}:us-east-1:{ACCOUNT}:instance/{name}"


@pytest.mark.asyncio
async def test_active_findings_become_findings_covered_and_uncovered(
    adapter: AWSAdapter,
) -> None:
    covered = _snap("bucket-a")
    findings_in = [
        _asff(
            finding_id="f1", title="Archived issue", label="HIGH",
            arn=_arn("s3", "bucket-a"), record_state="ARCHIVED",
        ),
        _asff(
            finding_id="f2", title="S3 public access", label="MEDIUM",
            arn=_arn("s3", "bucket-a"),
            standards=["standards/cis-aws-foundations-benchmark/v/1.4.0"],
        ),
        _asff(
            finding_id="f3", title="GuardDuty recon", label="CRITICAL",
            arn=_arn("ec2", "i-abc123"), rtype="AwsEc2Instance",
        ),
    ]
    fake = _FakeSecurityHub(findings_in)
    adapter._securityhub_client = MagicMock(return_value=fake)  # type: ignore[method-assign]

    out = await adapter.fetch_securityhub_findings([covered])

    names = {f.rule_name for f in out}
    assert names == {"S3 public access", "GuardDuty recon"}
    assert all(f.finding_type == FindingType.SECURITY for f in out)
    assert all(f.priority_score > 0 for f in out)

    uncovered = next(f for f in out if f.rule_name == "GuardDuty recon")
    assert uncovered.evidence["arn"] == _arn("ec2", "i-abc123")
    assert uncovered.resource_snapshot is not None
    assert uncovered.resource_snapshot.resource_name == "i-abc123"

    covered_finding = next(f for f in out if f.rule_name == "S3 public access")
    assert covered_finding.compliance_frameworks  # mapped from standards
    assert covered.data_tier == DataTier.TIER2_ENRICHED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("MEDIUM", Severity.MEDIUM),
        ("LOW", Severity.LOW),
        ("INFORMATIONAL", Severity.INFORMATIONAL),
        ("weird", Severity.MEDIUM),
    ],
)
async def test_severity_mapping(
    adapter: AWSAdapter, label: str, expected: Severity,
) -> None:
    f = _asff(
        finding_id="f1", title="x", label=label, arn=_arn("s3", "bucket-a"),
    )
    adapter._securityhub_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeSecurityHub([f]),
    )
    out = await adapter.fetch_securityhub_findings([_snap("bucket-a")])
    assert out[0].severity == expected


@pytest.mark.asyncio
async def test_securityhub_failure_returns_empty(adapter: AWSAdapter) -> None:
    adapter._securityhub_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeSecurityHub([], raises=True),
    )
    out = await adapter.fetch_securityhub_findings([_snap("bucket-a")])
    assert out == []


@pytest.mark.asyncio
async def test_tier2_unavailable_makes_no_calls(adapter: AWSAdapter) -> None:
    client_factory = MagicMock()
    adapter._securityhub_client = client_factory  # type: ignore[method-assign]
    flags = CapabilityFlags(tier1_available=True, tier2_available=False)
    out = await adapter.fetch_securityhub_findings([_snap("bucket-a")], flags=flags)
    assert out == []
    client_factory.assert_not_called()


@pytest.mark.asyncio
async def test_deterministic_finding_id_stable(adapter: AWSAdapter) -> None:
    f = _asff(
        finding_id="f1", title="x", label="HIGH", arn=_arn("s3", "bucket-a"),
    )
    adapter._securityhub_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeSecurityHub([f]),
    )
    first = await adapter.fetch_securityhub_findings([_snap("bucket-a")])
    adapter._securityhub_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeSecurityHub([f]),
    )
    second = await adapter.fetch_securityhub_findings([_snap("bucket-a")])
    assert first[0].finding_id == second[0].finding_id


@pytest.mark.asyncio
async def test_overlap_marks_native_rule_for_dedup(
    adapter: AWSAdapter, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        adapter_module.SECURITYHUB_TO_NATIVE_RULE,
        "S3.8 block public access",
        "AWS-S3-002",
    )
    f = _asff(
        finding_id="f1", title="S3.8 block public access", label="HIGH",
        arn=_arn("s3", "bucket-a"),
    )
    adapter._securityhub_client = MagicMock(  # type: ignore[method-assign]
        return_value=_FakeSecurityHub([f]),
    )
    out = await adapter.fetch_securityhub_findings([_snap("bucket-a")])
    assert out[0].evidence["native_rule_overlap"] == "AWS-S3-002"
    assert out[0].evidence["resource_key"] == "aws-global/bucket-a"
