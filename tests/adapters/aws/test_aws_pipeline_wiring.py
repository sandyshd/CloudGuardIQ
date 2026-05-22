"""Tests for cross-cloud wiring: PolicyEngine discovery + adapter factory + ScanPipeline."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from cloudguardiq.adapters.aws.adapter import AWSAdapter
from cloudguardiq.adapters.factory import (
    UnsupportedProviderError,
    build_scan_adapter,
)
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import ResourceSnapshot
from cloudguardiq.pipeline.scan_pipeline import ScanPipeline
from cloudguardiq.policy.engine import PolicyEngine


def _aws_snap(resource_type: str, config: dict, name: str = "r1") -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id="111122223333",
        resource_group="aws-global",
        resource_type=resource_type,
        resource_name=name,
        region="us-east-1",
        provider=CloudProvider.AWS,
        data_tier=DataTier.TIER1_NATIVE,
        config=config,
    )


def _azure_snap(resource_type: str, config: dict, name: str = "az1") -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id="sub-1",
        resource_group="rg-1",
        resource_type=resource_type,
        resource_name=name,
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config=config,
    )


# ---------------------------------------------------------------------------
# PolicyEngine auto-discovery now recursively picks up AWS rules
# ---------------------------------------------------------------------------


class TestPolicyEngineDiscovery:
    def test_default_engine_discovers_aws_and_azure_rules(self) -> None:
        engine = PolicyEngine()
        rule_ids = {getattr(r, "rule_id", "") for r in engine._native_rules}  # noqa: SLF001
        # Azure rule (existing)
        assert "STOR-001" in rule_ids
        # AWS rules (new)
        assert "AWS-S3-001" in rule_ids
        assert "AWS-EC2-001" in rule_ids
        assert "AWS-SG-001" in rule_ids
        assert "AWS-IAM-001" in rule_ids
        assert "AWS-FINOPS-001" in rule_ids

    def test_aws_rule_does_not_fire_on_azure_snapshot(self) -> None:
        """Cross-cloud routing: AWS-S3-001 must NOT match an Azure storage snap."""
        engine = PolicyEngine()
        snap = _azure_snap(
            "Microsoft.Storage/storageAccounts",
            {"allow_blob_public_access": True},
        )
        findings = engine.evaluate([snap])
        rule_ids = {f.rule_id for f in findings}
        assert "AWS-S3-001" not in rule_ids
        assert "AWS-S3-002" not in rule_ids
        assert "AWS-S3-003" not in rule_ids
        # Azure rule still fires
        assert "STOR-001" in rule_ids

    def test_azure_rule_does_not_fire_on_aws_snapshot(self) -> None:
        engine = PolicyEngine()
        snap = _aws_snap("AWS::S3::Bucket", {"acl": {"Grants": []}})
        findings = engine.evaluate([snap])
        rule_ids = {f.rule_id for f in findings}
        assert "STOR-001" not in rule_ids
        # AWS-S3-003 (missing encryption) should fire
        assert "AWS-S3-003" in rule_ids


# ---------------------------------------------------------------------------
# Adapter factory
# ---------------------------------------------------------------------------


class TestAdapterFactory:
    def test_builds_aws_adapter(self) -> None:
        adapter = build_scan_adapter(
            CloudProvider.AWS,
            account_id="111122223333",
            region="us-west-2",
            boto3_session=MagicMock(),
        )
        assert isinstance(adapter, AWSAdapter)
        assert adapter.account_id == "111122223333"
        assert adapter.region == "us-west-2"

    def test_accepts_string_provider(self) -> None:
        adapter = build_scan_adapter(
            "AWS", account_id="111122223333", boto3_session=MagicMock()
        )
        assert isinstance(adapter, AWSAdapter)

    def test_aws_without_account_id_raises(self) -> None:
        with pytest.raises(UnsupportedProviderError):
            build_scan_adapter(CloudProvider.AWS)

    def test_azure_requires_subscription_and_credential(self) -> None:
        with pytest.raises(UnsupportedProviderError):
            build_scan_adapter(CloudProvider.AZURE)

    def test_unknown_provider_raises(self) -> None:
        with pytest.raises(Exception):  # noqa: B017 - enum coercion may raise ValueError
            build_scan_adapter("MARS")


# ---------------------------------------------------------------------------
# End-to-end: ScanPipeline + AWSAdapter + PolicyEngine produce AWS findings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_pipeline_runs_end_to_end_with_aws_adapter() -> None:
    """An AWS-snapshot scan produces AWS findings tagged with tenant_id."""
    snaps = [
        # S3 bucket with public ACL grant + no encryption
        _aws_snap(
            "AWS::S3::Bucket",
            {
                "acl": {
                    "Grants": [
                        {
                            "Grantee": {
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                            },
                            "Permission": "READ",
                        }
                    ]
                },
                "public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                "encryption": {},
            },
            name="public-bucket",
        ),
        # SG open on port 22 to 0.0.0.0/0
        _aws_snap(
            "AWS::EC2::SecurityGroup",
            {
                "ingress_rules": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ]
            },
            name="sg-1",
        ),
    ]

    adapter = MagicMock()
    adapter.scan = AsyncMock(return_value=snaps)

    db = MagicMock()
    db.save_finding = AsyncMock()
    db.mark_unseen_findings_resolved = AsyncMock()
    db.save_scan_result = AsyncMock()
    # ScanPipeline._save_scan_result calls upsert_item under the hood; stub it
    db._db = MagicMock()
    container = MagicMock()
    container.upsert_item = AsyncMock()
    db._db.get_container_client = MagicMock(return_value=container)

    pipeline = ScanPipeline(
        adapter=adapter,
        policy_engine=PolicyEngine(),
        ai_engine=None,
        db=db,
        service_bus_sender=None,
    )

    result = await pipeline.run("111122223333", tenant_id="tenant-x")

    assert result.resources_scanned == 2
    assert result.findings_count >= 2  # at least S3 public ACL + SG SSH-open
    saved_findings = [
        call.args[0] for call in db.save_finding.await_args_list
    ]
    rule_ids = {f.rule_id for f in saved_findings}
    assert "AWS-S3-001" in rule_ids
    assert "AWS-S3-003" in rule_ids
    assert "AWS-SG-001" in rule_ids
    # Tenant stamping
    for f in saved_findings:
        assert f.tenant_id == "tenant-x"
        assert f.resource_snapshot.tenant_id == "tenant-x"
