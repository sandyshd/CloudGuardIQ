"""Tests for the AWS rule pack (11 rules — pass & fail cases)."""

from __future__ import annotations

from typing import Any

from cloudguardiq.adapters.rules.aws.ec2 import (
    EbsEncryptionRule,
    InstancePublicIpRule,
    UnattachedEbsVolumeRule,
)
from cloudguardiq.adapters.rules.aws.finops import UnattachedEipRule
from cloudguardiq.adapters.rules.aws.iam import (
    IamUserNoMfaRule,
    RootAccessKeysRule,
)
from cloudguardiq.adapters.rules.aws.registry import AWS_RULE_REGISTRY
from cloudguardiq.adapters.rules.aws.s3 import (
    S3BucketEncryptionRule,
    S3PublicAccessBlockRule,
    S3PublicAclRule,
)
from cloudguardiq.adapters.rules.aws.security_group import (
    RDPOpenToInternetRule,
    SSHOpenToInternetRule,
)
from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import ResourceSnapshot


def _snap(resource_type: str, config: dict[str, Any], name: str = "r1") -> ResourceSnapshot:
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


# ---------------------------------------------------------------------------
# Registry sanity
# ---------------------------------------------------------------------------


def test_registry_contains_eleven_unique_rules() -> None:
    rule_ids = [r.rule_id for r in AWS_RULE_REGISTRY]
    assert len(rule_ids) == 11
    assert len(set(rule_ids)) == 11


def test_every_registered_rule_targets_aws_resource_types() -> None:
    for r in AWS_RULE_REGISTRY:
        for rt in r.resource_types:
            assert rt.startswith("AWS::"), f"{r.rule_id} targets {rt}"


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------


class TestS3PublicAcl:
    def test_fail_when_acl_grants_allusers(self) -> None:
        snap = _snap(
            "AWS::S3::Bucket",
            {
                "acl": {
                    "Grants": [
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                            },
                            "Permission": "READ",
                        }
                    ]
                }
            },
        )
        result = S3PublicAclRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-S3-001"
        assert result.severity is Severity.CRITICAL

    def test_pass_when_only_owner_grant(self) -> None:
        snap = _snap(
            "AWS::S3::Bucket",
            {
                "acl": {
                    "Grants": [
                        {
                            "Grantee": {
                                "Type": "CanonicalUser",
                                "ID": "abc",
                            },
                            "Permission": "FULL_CONTROL",
                        }
                    ]
                }
            },
        )
        assert S3PublicAclRule().evaluate(snap) is None


class TestS3PublicAccessBlock:
    def test_fail_when_settings_missing(self) -> None:
        snap = _snap(
            "AWS::S3::Bucket",
            {
                "public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": False,
                }
            },
        )
        result = S3PublicAccessBlockRule().evaluate(snap)
        assert result is not None
        assert "IgnorePublicAcls" in result.evidence["missing_settings"]
        assert "RestrictPublicBuckets" in result.evidence["missing_settings"]

    def test_pass_when_fully_enabled(self) -> None:
        snap = _snap(
            "AWS::S3::Bucket",
            {
                "public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            },
        )
        assert S3PublicAccessBlockRule().evaluate(snap) is None


class TestS3BucketEncryption:
    def test_fail_when_no_rules(self) -> None:
        snap = _snap("AWS::S3::Bucket", {"encryption": {}})
        result = S3BucketEncryptionRule().evaluate(snap)
        assert result is not None
        assert result.severity is Severity.HIGH

    def test_pass_when_sse_configured(self) -> None:
        snap = _snap(
            "AWS::S3::Bucket",
            {
                "encryption": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                }
            },
        )
        assert S3BucketEncryptionRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# EC2 / EBS
# ---------------------------------------------------------------------------


class TestEbsEncryption:
    def test_fail_when_not_encrypted(self) -> None:
        snap = _snap("AWS::EC2::Volume", {"encrypted": False, "state": "in-use"})
        result = EbsEncryptionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-EC2-001"

    def test_pass_when_encrypted(self) -> None:
        snap = _snap("AWS::EC2::Volume", {"encrypted": True})
        assert EbsEncryptionRule().evaluate(snap) is None


class TestInstancePublicIp:
    def test_fail_when_public_ip_present(self) -> None:
        snap = _snap("AWS::EC2::Instance", {"public_ip_address": "54.1.2.3"})
        result = InstancePublicIpRule().evaluate(snap)
        assert result is not None
        assert result.severity is Severity.MEDIUM

    def test_pass_when_no_public_ip(self) -> None:
        snap = _snap("AWS::EC2::Instance", {"public_ip_address": None})
        assert InstancePublicIpRule().evaluate(snap) is None


class TestUnattachedEbsVolume:
    def test_fail_when_available(self) -> None:
        snap = _snap(
            "AWS::EC2::Volume",
            {"state": "available", "size": 100, "encrypted": True},
        )
        result = UnattachedEbsVolumeRule().evaluate(snap)
        assert result is not None
        assert result.finding_type is FindingType.FINOPS

    def test_pass_when_in_use(self) -> None:
        snap = _snap("AWS::EC2::Volume", {"state": "in-use"})
        assert UnattachedEbsVolumeRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------


def _sg_config(port: int, cidr: str, protocol: str = "tcp") -> dict[str, Any]:
    return {
        "ingress_rules": [
            {
                "IpProtocol": protocol,
                "FromPort": port,
                "ToPort": port,
                "IpRanges": [{"CidrIp": cidr}],
            }
        ]
    }


class TestSSHOpenToInternet:
    def test_fail_when_22_open_to_world(self) -> None:
        snap = _snap("AWS::EC2::SecurityGroup", _sg_config(22, "0.0.0.0/0"))
        assert SSHOpenToInternetRule().evaluate(snap) is not None

    def test_pass_when_22_open_to_private_cidr(self) -> None:
        snap = _snap("AWS::EC2::SecurityGroup", _sg_config(22, "10.0.0.0/8"))
        assert SSHOpenToInternetRule().evaluate(snap) is None


class TestRDPOpenToInternet:
    def test_fail_when_3389_open_to_world(self) -> None:
        snap = _snap("AWS::EC2::SecurityGroup", _sg_config(3389, "0.0.0.0/0"))
        assert RDPOpenToInternetRule().evaluate(snap) is not None

    def test_pass_when_no_3389(self) -> None:
        snap = _snap("AWS::EC2::SecurityGroup", _sg_config(443, "0.0.0.0/0"))
        assert RDPOpenToInternetRule().evaluate(snap) is None


def test_protocol_all_opens_every_port() -> None:
    snap = _snap(
        "AWS::EC2::SecurityGroup",
        {
            "ingress_rules": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        },
    )
    assert SSHOpenToInternetRule().evaluate(snap) is not None
    assert RDPOpenToInternetRule().evaluate(snap) is not None


# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------


class TestRootAccessKeys:
    def test_fail_when_root_has_keys(self) -> None:
        snap = _snap(
            "AWS::IAM::AccountSummary",
            {"summary_map": {"AccountAccessKeysPresent": 1}},
            name="111122223333",
        )
        result = RootAccessKeysRule().evaluate(snap)
        assert result is not None
        assert result.severity is Severity.CRITICAL

    def test_pass_when_root_has_no_keys(self) -> None:
        snap = _snap(
            "AWS::IAM::AccountSummary",
            {"summary_map": {"AccountAccessKeysPresent": 0}},
        )
        assert RootAccessKeysRule().evaluate(snap) is None


class TestIamUserNoMfa:
    def test_fail_when_console_user_without_mfa(self) -> None:
        snap = _snap(
            "AWS::IAM::User",
            {"password_enabled": True, "mfa_active": False},
            name="alice",
        )
        result = IamUserNoMfaRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-IAM-002"

    def test_pass_when_user_has_mfa(self) -> None:
        snap = _snap(
            "AWS::IAM::User",
            {"password_enabled": True, "mfa_active": True},
        )
        assert IamUserNoMfaRule().evaluate(snap) is None

    def test_pass_when_no_console_access(self) -> None:
        snap = _snap(
            "AWS::IAM::User",
            {"password_enabled": False, "mfa_active": False},
        )
        assert IamUserNoMfaRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# FinOps
# ---------------------------------------------------------------------------


class TestUnattachedEip:
    def test_fail_when_no_association(self) -> None:
        snap = _snap(
            "AWS::EC2::EIP",
            {"association_id": None, "public_ip": "54.1.2.3"},
            name="eipalloc-1",
        )
        result = UnattachedEipRule().evaluate(snap)
        assert result is not None
        assert result.finding_type is FindingType.FINOPS

    def test_pass_when_associated(self) -> None:
        snap = _snap(
            "AWS::EC2::EIP",
            {"association_id": "eipassoc-x", "public_ip": "54.1.2.3"},
        )
        assert UnattachedEipRule().evaluate(snap) is None
