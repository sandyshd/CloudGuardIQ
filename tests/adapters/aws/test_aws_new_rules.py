"""Pass/fail tests for new AWS rules (RDS, Lambda, CloudTrail, EKS, KMS)."""

from __future__ import annotations

from typing import Any

from cloudguardiq.adapters.rules.aws.cloudtrail import (
    CloudTrailLogFileValidationRule,
    CloudTrailMultiRegionRule,
    CloudTrailNotLoggingRule,
)
from cloudguardiq.adapters.rules.aws.eks import (
    EksControlPlaneLoggingRule,
    EksPublicEndpointRule,
    EksSecretsEncryptionRule,
)
from cloudguardiq.adapters.rules.aws.kms import KmsKeyRotationRule
from cloudguardiq.adapters.rules.aws.lambda_ import (
    LambdaEnvVarKmsKeyRule,
    LambdaOutdatedRuntimeRule,
    LambdaPublicFunctionUrlRule,
)
from cloudguardiq.adapters.rules.aws.rds import (
    RdsBackupRetentionRule,
    RdsPubliclyAccessibleRule,
    RdsStorageEncryptionRule,
)
from cloudguardiq.core.enums import CloudProvider, DataTier, Severity
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
# RDS
# ---------------------------------------------------------------------------


class TestRdsStorageEncryption:
    def test_fail_when_unencrypted(self) -> None:
        snap = _snap("AWS::RDS::DBInstance", {"storage_encrypted": False})
        result = RdsStorageEncryptionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-RDS-001"
        assert result.severity is Severity.HIGH

    def test_pass_when_encrypted(self) -> None:
        snap = _snap("AWS::RDS::DBInstance", {"storage_encrypted": True})
        assert RdsStorageEncryptionRule().evaluate(snap) is None


class TestRdsPubliclyAccessible:
    def test_fail_when_public(self) -> None:
        snap = _snap("AWS::RDS::DBInstance", {"publicly_accessible": True})
        result = RdsPubliclyAccessibleRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-RDS-002"
        assert result.severity is Severity.CRITICAL

    def test_pass_when_private(self) -> None:
        snap = _snap("AWS::RDS::DBInstance", {"publicly_accessible": False})
        assert RdsPubliclyAccessibleRule().evaluate(snap) is None


class TestRdsBackupRetention:
    def test_fail_when_short(self) -> None:
        snap = _snap("AWS::RDS::DBInstance", {"backup_retention_period": 3})
        result = RdsBackupRetentionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-RDS-003"

    def test_pass_when_seven_days(self) -> None:
        snap = _snap("AWS::RDS::DBInstance", {"backup_retention_period": 7})
        assert RdsBackupRetentionRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------


class TestLambdaEnvVarKmsKey:
    def test_fail_when_env_vars_and_no_cmk(self) -> None:
        snap = _snap(
            "AWS::Lambda::Function",
            {"environment_variables": {"K": "v"}, "kms_key_arn": ""},
        )
        result = LambdaEnvVarKmsKeyRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-LAM-001"

    def test_pass_when_cmk_set(self) -> None:
        snap = _snap(
            "AWS::Lambda::Function",
            {
                "environment_variables": {"K": "v"},
                "kms_key_arn": "arn:aws:kms:us-east-1:111:key/abc",
            },
        )
        assert LambdaEnvVarKmsKeyRule().evaluate(snap) is None

    def test_pass_when_no_env_vars(self) -> None:
        snap = _snap("AWS::Lambda::Function", {"environment_variables": {}})
        assert LambdaEnvVarKmsKeyRule().evaluate(snap) is None


class TestLambdaPublicFunctionUrl:
    def test_fail_when_auth_none(self) -> None:
        snap = _snap(
            "AWS::Lambda::Function",
            {"function_url_config": {"auth_type": "NONE"}},
        )
        result = LambdaPublicFunctionUrlRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-LAM-002"

    def test_pass_when_aws_iam(self) -> None:
        snap = _snap(
            "AWS::Lambda::Function",
            {"function_url_config": {"auth_type": "AWS_IAM"}},
        )
        assert LambdaPublicFunctionUrlRule().evaluate(snap) is None

    def test_pass_when_no_url(self) -> None:
        snap = _snap("AWS::Lambda::Function", {})
        assert LambdaPublicFunctionUrlRule().evaluate(snap) is None


class TestLambdaOutdatedRuntime:
    def test_fail_on_deprecated(self) -> None:
        snap = _snap("AWS::Lambda::Function", {"runtime": "python3.7"})
        result = LambdaOutdatedRuntimeRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-LAM-003"

    def test_pass_on_supported(self) -> None:
        snap = _snap("AWS::Lambda::Function", {"runtime": "python3.12"})
        assert LambdaOutdatedRuntimeRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------


class TestCloudTrailMultiRegion:
    def test_fail_when_single_region(self) -> None:
        snap = _snap("AWS::CloudTrail::Trail", {"is_multi_region_trail": False})
        result = CloudTrailMultiRegionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-CT-001"

    def test_pass_when_multi_region(self) -> None:
        snap = _snap("AWS::CloudTrail::Trail", {"is_multi_region_trail": True})
        assert CloudTrailMultiRegionRule().evaluate(snap) is None


class TestCloudTrailNotLogging:
    def test_fail_when_not_logging(self) -> None:
        snap = _snap("AWS::CloudTrail::Trail", {"is_logging": False})
        result = CloudTrailNotLoggingRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-CT-002"
        assert result.severity is Severity.CRITICAL

    def test_pass_when_logging(self) -> None:
        snap = _snap("AWS::CloudTrail::Trail", {"is_logging": True})
        assert CloudTrailNotLoggingRule().evaluate(snap) is None


class TestCloudTrailLogFileValidation:
    def test_fail_when_disabled(self) -> None:
        snap = _snap(
            "AWS::CloudTrail::Trail", {"log_file_validation_enabled": False}
        )
        result = CloudTrailLogFileValidationRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-CT-003"

    def test_pass_when_enabled(self) -> None:
        snap = _snap(
            "AWS::CloudTrail::Trail", {"log_file_validation_enabled": True}
        )
        assert CloudTrailLogFileValidationRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# EKS
# ---------------------------------------------------------------------------


class TestEksPublicEndpoint:
    def test_fail_when_public_open(self) -> None:
        snap = _snap(
            "AWS::EKS::Cluster",
            {"endpoint_public_access": True, "public_access_cidrs": ["0.0.0.0/0"]},
        )
        result = EksPublicEndpointRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-EKS-001"

    def test_pass_when_private(self) -> None:
        snap = _snap("AWS::EKS::Cluster", {"endpoint_public_access": False})
        assert EksPublicEndpointRule().evaluate(snap) is None

    def test_pass_when_restricted_cidrs(self) -> None:
        snap = _snap(
            "AWS::EKS::Cluster",
            {"endpoint_public_access": True, "public_access_cidrs": ["10.0.0.0/8"]},
        )
        assert EksPublicEndpointRule().evaluate(snap) is None


class TestEksControlPlaneLogging:
    def test_fail_when_partial(self) -> None:
        snap = _snap(
            "AWS::EKS::Cluster", {"enabled_log_types": ["api"]}
        )
        result = EksControlPlaneLoggingRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-EKS-002"

    def test_pass_when_all_required(self) -> None:
        snap = _snap(
            "AWS::EKS::Cluster",
            {"enabled_log_types": ["api", "audit", "authenticator"]},
        )
        assert EksControlPlaneLoggingRule().evaluate(snap) is None


class TestEksSecretsEncryption:
    def test_fail_when_no_kms_key(self) -> None:
        snap = _snap("AWS::EKS::Cluster", {"secrets_kms_key_arn": ""})
        result = EksSecretsEncryptionRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-EKS-003"

    def test_pass_when_kms_key_set(self) -> None:
        snap = _snap(
            "AWS::EKS::Cluster",
            {"secrets_kms_key_arn": "arn:aws:kms:us-east-1:111:key/abc"},
        )
        assert EksSecretsEncryptionRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# KMS
# ---------------------------------------------------------------------------


class TestKmsKeyRotation:
    def test_fail_when_disabled_on_customer_key(self) -> None:
        snap = _snap(
            "AWS::KMS::Key",
            {
                "key_manager": "CUSTOMER",
                "origin": "AWS_KMS",
                "key_rotation_enabled": False,
            },
        )
        result = KmsKeyRotationRule().evaluate(snap)
        assert result is not None
        assert result.rule_id == "AWS-KMS-001"

    def test_pass_when_rotation_enabled(self) -> None:
        snap = _snap(
            "AWS::KMS::Key",
            {
                "key_manager": "CUSTOMER",
                "origin": "AWS_KMS",
                "key_rotation_enabled": True,
            },
        )
        assert KmsKeyRotationRule().evaluate(snap) is None

    def test_pass_when_aws_managed(self) -> None:
        snap = _snap(
            "AWS::KMS::Key",
            {"key_manager": "AWS", "key_rotation_enabled": False},
        )
        assert KmsKeyRotationRule().evaluate(snap) is None

    def test_pass_when_external_origin(self) -> None:
        snap = _snap(
            "AWS::KMS::Key",
            {
                "key_manager": "CUSTOMER",
                "origin": "EXTERNAL",
                "key_rotation_enabled": False,
            },
        )
        assert KmsKeyRotationRule().evaluate(snap) is None
