"""Tests for AWSAdapter — boto3 fully mocked."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from cloudguardiq.adapters.aws.adapter import AWSAdapter
from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import FindingResult


def _fake_session() -> MagicMock:
    """Build a fake boto3.Session whose .client(svc) returns service mocks."""
    session = MagicMock(name="Session")

    s3 = MagicMock(name="s3")
    s3.list_buckets.return_value = {
        "Buckets": [{"Name": "bucket-a"}, {"Name": "bucket-b"}]
    }
    s3.get_bucket_acl.return_value = {"Grants": []}
    s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {"Rules": [{"x": 1}]}
    }
    s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}

    ec2 = MagicMock(name="ec2")

    def _paginator(op_name: str) -> MagicMock:
        p = MagicMock(name=f"paginator-{op_name}")
        if op_name == "describe_volumes":
            p.paginate.return_value = [
                {
                    "Volumes": [
                        {
                            "VolumeId": "vol-1",
                            "Encrypted": False,
                            "State": "available",
                            "Size": 50,
                            "AvailabilityZone": "us-east-1a",
                            "Attachments": [],
                            "VolumeType": "gp3",
                            "Tags": [{"Key": "env", "Value": "dev"}],
                        }
                    ]
                }
            ]
        elif op_name == "describe_instances":
            p.paginate.return_value = [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-1",
                                    "State": {"Name": "running"},
                                    "PublicIpAddress": "54.1.2.3",
                                    "InstanceType": "t3.micro",
                                    "VpcId": "vpc-1",
                                    "Tags": [],
                                }
                            ]
                        }
                    ]
                }
            ]
        elif op_name == "describe_security_groups":
            p.paginate.return_value = [
                {
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-1",
                            "GroupName": "default",
                            "VpcId": "vpc-1",
                            "IpPermissions": [
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 22,
                                    "ToPort": 22,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                }
                            ],
                            "IpPermissionsEgress": [],
                        }
                    ]
                }
            ]
        else:
            p.paginate.return_value = []
        return p

    ec2.get_paginator.side_effect = _paginator
    ec2.describe_addresses.return_value = {
        "Addresses": [
            {
                "AllocationId": "eipalloc-1",
                "PublicIp": "54.9.9.9",
                "AssociationId": None,
                "Domain": "vpc",
            }
        ]
    }

    iam = MagicMock(name="iam")
    iam.get_account_summary.return_value = {
        "SummaryMap": {"AccountAccessKeysPresent": 1}
    }
    user_paginator = MagicMock()
    user_paginator.paginate.return_value = [
        {
            "Users": [
                {
                    "UserName": "alice",
                    "UserId": "u1",
                    "Arn": "arn",
                    "PasswordLastUsed": "2026-01-01",
                }
            ]
        }
    ]
    iam.get_paginator.return_value = user_paginator
    iam.list_mfa_devices.return_value = {"MFADevices": []}

    sts = MagicMock(name="sts")
    sts.get_caller_identity.return_value = {"Account": "111122223333"}

    def _client(name: str) -> MagicMock:
        return {"s3": s3, "ec2": ec2, "iam": iam, "sts": sts}[name]

    session.client.side_effect = _client
    return session


@pytest.mark.asyncio
async def test_scan_returns_snapshots_for_all_supported_resource_types() -> None:
    adapter = AWSAdapter(
        account_id="111122223333", region="us-east-1", session=_fake_session()
    )
    snaps = await adapter.scan()
    types = {s.resource_type for s in snaps}
    assert {
        "AWS::S3::Bucket",
        "AWS::EC2::Volume",
        "AWS::EC2::Instance",
        "AWS::EC2::SecurityGroup",
        "AWS::IAM::AccountSummary",
        "AWS::IAM::User",
        "AWS::EC2::EIP",
    }.issubset(types)
    for s in snaps:
        assert s.provider is CloudProvider.AWS
        assert s.data_tier is DataTier.TIER1_NATIVE
        assert s.subscription_id == "111122223333"


@pytest.mark.asyncio
async def test_validate_connection_true_when_sts_succeeds() -> None:
    adapter = AWSAdapter(
        account_id="111122223333", session=_fake_session()
    )
    assert await adapter.validate_connection() is True


@pytest.mark.asyncio
async def test_validate_connection_false_when_sts_raises() -> None:
    session = _fake_session()
    sts = session.client("sts")
    sts.get_caller_identity.side_effect = RuntimeError("boom")
    adapter = AWSAdapter(account_id="111122223333", session=session)
    assert await adapter.validate_connection() is False


@pytest.mark.asyncio
async def test_get_api_contract_lists_aws_operations() -> None:
    adapter = AWSAdapter(account_id="111122223333", session=_fake_session())
    contract = await adapter.get_api_contract()
    assert contract["provider"] == "AWS"
    assert "s3:ListBuckets" in contract["operations"]
    assert "ec2:DescribeSecurityGroups" in contract["operations"]


@pytest.mark.asyncio
async def test_legacy_methods_return_safe_defaults() -> None:
    adapter = AWSAdapter(account_id="111122223333", session=_fake_session())
    assert await adapter.get_resource("any") is None
    assert await adapter.get_cost("any") == 0.0
    assert await adapter.get_raw_properties("any") == {}
    snaps = await adapter.scan()
    assert await adapter.enrich_with_defender(snaps) == snaps


@pytest.mark.asyncio
async def test_scan_populates_policy_findings() -> None:
    adapter = AWSAdapter(
        account_id="111122223333", region="us-east-1", session=_fake_session()
    )
    policy = FindingResult(
        rule_id="AWSPOL-CIS_1_2",
        severity=Severity.HIGH,
        finding_type=FindingType.COMPLIANCE,
    )
    adapter._policy_adapter.fetch_findings = AsyncMock(return_value=[policy])  # type: ignore[method-assign]

    await adapter.scan()

    assert len(adapter.policy_findings) == 1
    assert adapter.policy_findings[0].rule_id == "AWSPOL-CIS_1_2"

