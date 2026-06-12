"""Tests for AWSPolicyComplianceAdapter."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from cloudguardiq.adapters.aws.aws_policy_compliance_adapter import (
    FRAMEWORK_STANDARDS,
    AWSPolicyComplianceAdapter,
)
from cloudguardiq.core.enums import DataTier, FindingType, Severity

ACCOUNT_ID = "111122223333"
CIS_ARN = FRAMEWORK_STANDARDS["CIS_AZURE"]
NIST_ARN = FRAMEWORK_STANDARDS["NIST_800_53"]


def _finding_row(
    *,
    resource_id: str = "arn:aws:s3:::bucket-a",
    generator: str = "security-control/CIS.1.2",
    title: str = "CIS.1.2 S3 bucket should block public access",
    updated_at: str = "2026-05-01T00:00:00Z",
) -> dict:
    return {
        "Id": "arn:aws:securityhub:us-east-1::finding/abc",
        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "GeneratorId": generator,
        "Title": title,
        "Description": "Control failed",
        "Severity": {"Label": "HIGH"},
        "Compliance": {"Status": "FAILED"},
        "UpdatedAt": updated_at,
        "Resources": [
            {
                "Id": resource_id,
                "Type": "AwsS3Bucket",
            }
        ],
    }


@pytest.fixture
def adapter() -> AWSPolicyComplianceAdapter:
    return AWSPolicyComplianceAdapter(
        account_id=ACCOUNT_ID,
        region="us-east-1",
        session=MagicMock(),
        standards=[CIS_ARN, NIST_ARN],
    )


@pytest.mark.asyncio
async def test_fetch_findings_returns_empty_when_no_standard_enabled(
    adapter: AWSPolicyComplianceAdapter,
) -> None:
    adapter._list_enabled_standards = AsyncMock(return_value=set())  # type: ignore[attr-defined]
    assert await adapter.fetch_findings() == []


@pytest.mark.asyncio
async def test_fetch_findings_skips_unenabled_standard(
    adapter: AWSPolicyComplianceAdapter,
) -> None:
    adapter._list_enabled_standards = AsyncMock(return_value={NIST_ARN})  # type: ignore[attr-defined]
    query_spy = AsyncMock(return_value=[])  # type: ignore[attr-defined]
    adapter._query_non_compliant_findings = query_spy  # type: ignore[assignment]

    await adapter.fetch_findings()

    query_spy.assert_awaited_once_with(NIST_ARN)


@pytest.mark.asyncio
async def test_dedup_by_resource_and_control_keeps_latest(
    adapter: AWSPolicyComplianceAdapter,
) -> None:
    older = _finding_row(updated_at="2026-01-01T00:00:00Z")
    newer = _finding_row(updated_at="2026-02-01T00:00:00Z")

    adapter._list_enabled_standards = AsyncMock(return_value={CIS_ARN})  # type: ignore[attr-defined]
    adapter._query_non_compliant_findings = AsyncMock(return_value=[older, newer])  # type: ignore[attr-defined]

    findings = await adapter.fetch_findings()

    assert len(findings) == 1
    assert findings[0].evidence["updated_at"] == "2026-02-01T00:00:00Z"


def test_to_finding_maps_all_fields(adapter: AWSPolicyComplianceAdapter) -> None:
    finding = adapter._to_finding(_finding_row(), CIS_ARN)

    assert finding is not None
    assert finding.rule_id.startswith("AWSPOL-")
    assert finding.rule_name == "CIS.1.2 S3 bucket should block public access"
    assert finding.severity == Severity.HIGH
    assert finding.finding_type == FindingType.COMPLIANCE
    assert finding.compliance_frameworks == ["CIS_AZURE:CIS.1.2"]
    assert finding.resource_snapshot is not None
    assert finding.resource_snapshot.data_tier == DataTier.TIER1_NATIVE
    assert finding.resource_snapshot.provider.value == "AWS"


def test_to_finding_returns_none_when_required_fields_missing(
    adapter: AWSPolicyComplianceAdapter,
) -> None:
    row = _finding_row()
    row["Resources"] = []
    assert adapter._to_finding(row, CIS_ARN) is None


def test_to_finding_is_deterministic(adapter: AWSPolicyComplianceAdapter) -> None:
    first = adapter._to_finding(_finding_row(), CIS_ARN)
    second = adapter._to_finding(_finding_row(), CIS_ARN)
    assert first is not None and second is not None
    assert first.finding_id == second.finding_id


@pytest.mark.asyncio
async def test_validate_connection_true(adapter: AWSPolicyComplianceAdapter) -> None:
    client = MagicMock()
    client.get_enabled_standards.return_value = {"StandardsSubscriptions": []}
    adapter._securityhub_client = lambda: client  # type: ignore[method-assign]
    assert await adapter.validate_connection() is True


@pytest.mark.asyncio
async def test_validate_connection_false_on_error(adapter: AWSPolicyComplianceAdapter) -> None:
    client = MagicMock()
    client.get_enabled_standards.side_effect = RuntimeError("boom")
    adapter._securityhub_client = lambda: client  # type: ignore[method-assign]
    assert await adapter.validate_connection() is False


@pytest.mark.asyncio
async def test_scan_returns_empty_list(adapter: AWSPolicyComplianceAdapter) -> None:
    assert await adapter.scan() == []


@pytest.mark.asyncio
async def test_get_api_contract_returns_schema(adapter: AWSPolicyComplianceAdapter) -> None:
    adapter._query_non_compliant_findings = AsyncMock(return_value=[_finding_row()])  # type: ignore[attr-defined]
    contract = await adapter.get_api_contract()
    assert contract["provider"] == "aws"
    assert contract["endpoint"] == "securityhub.get_findings"
    assert "Title" in contract["schema"]


