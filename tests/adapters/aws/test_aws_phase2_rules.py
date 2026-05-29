"""Phase 2 AWS rule pack — pass/fail coverage for the 26 new rules."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cloudguardiq.adapters.rules.aws.apigateway import (
    ApiGatewayLoggingDisabledRule,
    ApiGatewayNoWafRule,
)
from cloudguardiq.adapters.rules.aws.cloudwatch import (
    LogGroupKmsKeyRule,
    LogGroupRetentionRule,
)
from cloudguardiq.adapters.rules.aws.dynamodb import (
    DynamoDbCmekEncryptionRule,
    DynamoDbPitrDisabledRule,
)
from cloudguardiq.adapters.rules.aws.ecr import (
    EcrScanOnPushRule,
    EcrTagImmutabilityRule,
)
from cloudguardiq.adapters.rules.aws.elasticache import (
    ElastiCacheAtRestEncryptionRule,
    ElastiCacheTransitEncryptionRule,
)
from cloudguardiq.adapters.rules.aws.elb import (
    ElbAccessLogsDisabledRule,
    ElbDeletionProtectionRule,
    ElbHttpListenerRule,
)
from cloudguardiq.adapters.rules.aws.governance import (
    ConfigRecorderDisabledRule,
    IamAccessKeyAgeRule,
    IamPasswordPolicyWeakRule,
    S3LoggingDisabledRule,
    S3VersioningDisabledRule,
)
from cloudguardiq.adapters.rules.aws.messaging import (
    SnsTopicEncryptionRule,
    SnsTopicPublicAccessRule,
    SqsQueueEncryptionRule,
    SqsQueuePublicAccessRule,
)
from cloudguardiq.adapters.rules.aws.secrets_acm import (
    AcmCertificateExpiringRule,
    SecretRotationDisabledRule,
)
from cloudguardiq.adapters.rules.aws.vpc import (
    DefaultSecurityGroupOpenRule,
    VpcFlowLogsDisabledRule,
)
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import ResourceSnapshot


def _snap(resource_type: str, name: str, config: dict) -> ResourceSnapshot:
    return ResourceSnapshot(
        tenant_id="t",
        provider=CloudProvider.AWS,
        subscription_id="123456789012",
        resource_group="us-east-1",
        resource_type=resource_type,
        resource_name=name,
        region="us-east-1",
        config=config,
        tags={},
        data_tier=DataTier.TIER1_NATIVE,
        captured_at=datetime.now(timezone.utc),
    )


# --- DynamoDB ----------------------------------------------------------------
def test_ddb_cmek_fires_when_no_kms_key() -> None:
    rule = DynamoDbCmekEncryptionRule()
    assert (
        rule.evaluate(_snap("AWS::DynamoDB::Table", "t", {"sse_description": {}}))
        is not None
    )


def test_ddb_cmek_passes_with_kms_key() -> None:
    rule = DynamoDbCmekEncryptionRule()
    cfg = {"sse_description": {"SSEType": "KMS", "KMSMasterKeyArn": "arn"}}
    assert rule.evaluate(_snap("AWS::DynamoDB::Table", "t", cfg)) is None


def test_ddb_pitr_fires_when_disabled() -> None:
    rule = DynamoDbPitrDisabledRule()
    assert (
        rule.evaluate(_snap("AWS::DynamoDB::Table", "t", {"pitr_enabled": False}))
        is not None
    )


def test_ddb_pitr_passes_when_enabled() -> None:
    rule = DynamoDbPitrDisabledRule()
    assert (
        rule.evaluate(_snap("AWS::DynamoDB::Table", "t", {"pitr_enabled": True}))
        is None
    )


# --- SNS / SQS ---------------------------------------------------------------
def test_sns_encryption_fires_without_kms() -> None:
    rule = SnsTopicEncryptionRule()
    assert rule.evaluate(_snap("AWS::SNS::Topic", "topic", {})) is not None


def test_sns_encryption_passes_with_kms() -> None:
    rule = SnsTopicEncryptionRule()
    cfg = {"kms_master_key_id": "alias/aws/sns"}
    assert rule.evaluate(_snap("AWS::SNS::Topic", "topic", cfg)) is None


def test_sns_public_policy_fires() -> None:
    rule = SnsTopicPublicAccessRule()
    cfg = {
        "policy": {
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*"}],
        },
    }
    assert rule.evaluate(_snap("AWS::SNS::Topic", "topic", cfg)) is not None


def test_sns_public_policy_passes_when_scoped() -> None:
    rule = SnsTopicPublicAccessRule()
    cfg = {
        "policy": {
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:role/x"}},
            ],
        },
    }
    assert rule.evaluate(_snap("AWS::SNS::Topic", "topic", cfg)) is None


def test_sqs_encryption_fires_without_sse() -> None:
    rule = SqsQueueEncryptionRule()
    assert rule.evaluate(_snap("AWS::SQS::Queue", "q", {})) is not None


def test_sqs_encryption_passes_when_sqs_managed() -> None:
    rule = SqsQueueEncryptionRule()
    cfg = {"sqs_managed_sse_enabled": True}
    assert rule.evaluate(_snap("AWS::SQS::Queue", "q", cfg)) is None


def test_sqs_public_policy_fires_when_star_aws() -> None:
    rule = SqsQueuePublicAccessRule()
    cfg = {
        "policy": '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"}}]}',
    }
    assert rule.evaluate(_snap("AWS::SQS::Queue", "q", cfg)) is not None


def test_sqs_public_policy_passes_without_policy() -> None:
    rule = SqsQueuePublicAccessRule()
    assert rule.evaluate(_snap("AWS::SQS::Queue", "q", {})) is None


# --- ELB ---------------------------------------------------------------------
def test_elb_http_listener_fires() -> None:
    rule = ElbHttpListenerRule()
    cfg = {"listeners": [{"protocol": "HTTP", "port": 80}]}
    assert (
        rule.evaluate(
            _snap("AWS::ElasticLoadBalancingV2::LoadBalancer", "alb", cfg),
        )
        is not None
    )


def test_elb_http_listener_passes_when_only_https() -> None:
    rule = ElbHttpListenerRule()
    cfg = {"listeners": [{"protocol": "HTTPS", "port": 443}]}
    assert (
        rule.evaluate(
            _snap("AWS::ElasticLoadBalancingV2::LoadBalancer", "alb", cfg),
        )
        is None
    )


def test_elb_access_logs_fires_when_disabled() -> None:
    rule = ElbAccessLogsDisabledRule()
    assert (
        rule.evaluate(
            _snap(
                "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "alb",
                {"access_logs_enabled": False},
            ),
        )
        is not None
    )


def test_elb_deletion_protection_fires() -> None:
    rule = ElbDeletionProtectionRule()
    assert (
        rule.evaluate(
            _snap(
                "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "alb",
                {"deletion_protection_enabled": False},
            ),
        )
        is not None
    )


# --- VPC ---------------------------------------------------------------------
def test_vpc_flow_logs_fires_when_disabled() -> None:
    rule = VpcFlowLogsDisabledRule()
    assert (
        rule.evaluate(_snap("AWS::EC2::VPC", "vpc", {"flow_logs_enabled": False}))
        is not None
    )


def test_vpc_flow_logs_passes_when_enabled() -> None:
    rule = VpcFlowLogsDisabledRule()
    assert (
        rule.evaluate(_snap("AWS::EC2::VPC", "vpc", {"flow_logs_enabled": True}))
        is None
    )


def test_default_sg_fires_when_default_has_rules() -> None:
    rule = DefaultSecurityGroupOpenRule()
    cfg = {
        "group_name": "default",
        "ip_permissions": [{"IpProtocol": "-1"}],
        "ip_permissions_egress": [],
    }
    assert rule.evaluate(_snap("AWS::EC2::SecurityGroup", "sg", cfg)) is not None


def test_default_sg_passes_when_named_default_has_no_rules() -> None:
    rule = DefaultSecurityGroupOpenRule()
    cfg = {
        "group_name": "default",
        "ip_permissions": [],
        "ip_permissions_egress": [],
    }
    assert rule.evaluate(_snap("AWS::EC2::SecurityGroup", "sg", cfg)) is None


def test_default_sg_skips_non_default_groups() -> None:
    rule = DefaultSecurityGroupOpenRule()
    cfg = {
        "group_name": "web",
        "ip_permissions": [{"IpProtocol": "tcp"}],
    }
    assert rule.evaluate(_snap("AWS::EC2::SecurityGroup", "sg", cfg)) is None


# --- CloudWatch Logs ---------------------------------------------------------
def test_log_retention_fires_when_below_365() -> None:
    rule = LogGroupRetentionRule()
    cfg = {"retention_in_days": 30}
    assert rule.evaluate(_snap("AWS::Logs::LogGroup", "lg", cfg)) is not None


def test_log_retention_passes_when_above_365() -> None:
    rule = LogGroupRetentionRule()
    cfg = {"retention_in_days": 400}
    assert rule.evaluate(_snap("AWS::Logs::LogGroup", "lg", cfg)) is None


def test_log_kms_fires_when_unset() -> None:
    rule = LogGroupKmsKeyRule()
    assert rule.evaluate(_snap("AWS::Logs::LogGroup", "lg", {})) is not None


def test_log_kms_passes_when_set() -> None:
    rule = LogGroupKmsKeyRule()
    cfg = {"kms_key_id": "arn:aws:kms:us-east-1:1:key/x"}
    assert rule.evaluate(_snap("AWS::Logs::LogGroup", "lg", cfg)) is None


# --- ECR ---------------------------------------------------------------------
def test_ecr_scan_on_push_fires_when_disabled() -> None:
    rule = EcrScanOnPushRule()
    assert (
        rule.evaluate(_snap("AWS::ECR::Repository", "r", {"scan_on_push": False}))
        is not None
    )


def test_ecr_tag_immutability_fires_when_mutable() -> None:
    rule = EcrTagImmutabilityRule()
    cfg = {"image_tag_mutability": "MUTABLE"}
    assert rule.evaluate(_snap("AWS::ECR::Repository", "r", cfg)) is not None


def test_ecr_tag_immutability_passes_when_immutable() -> None:
    rule = EcrTagImmutabilityRule()
    cfg = {"image_tag_mutability": "IMMUTABLE"}
    assert rule.evaluate(_snap("AWS::ECR::Repository", "r", cfg)) is None


# --- API Gateway -------------------------------------------------------------
def test_apigw_logging_fires_when_off() -> None:
    rule = ApiGatewayLoggingDisabledRule()
    assert rule.evaluate(_snap("AWS::ApiGateway::Stage", "stg", {})) is not None


def test_apigw_logging_passes_when_info() -> None:
    rule = ApiGatewayLoggingDisabledRule()
    cfg = {"logging_level": "INFO"}
    assert rule.evaluate(_snap("AWS::ApiGateway::Stage", "stg", cfg)) is None


def test_apigw_waf_fires_when_not_attached() -> None:
    rule = ApiGatewayNoWafRule()
    assert rule.evaluate(_snap("AWS::ApiGateway::Stage", "stg", {})) is not None


# --- Secrets Manager + ACM ---------------------------------------------------
def test_secret_rotation_fires_when_disabled() -> None:
    rule = SecretRotationDisabledRule()
    assert (
        rule.evaluate(
            _snap("AWS::SecretsManager::Secret", "s", {"rotation_enabled": False}),
        )
        is not None
    )


def test_acm_expiring_fires_when_within_30_days() -> None:
    rule = AcmCertificateExpiringRule()
    cfg = {"days_to_expiry": 7}
    assert (
        rule.evaluate(_snap("AWS::CertificateManager::Certificate", "c", cfg))
        is not None
    )


def test_acm_expiring_passes_when_distant() -> None:
    rule = AcmCertificateExpiringRule()
    cfg = {"days_to_expiry": 200}
    assert (
        rule.evaluate(_snap("AWS::CertificateManager::Certificate", "c", cfg))
        is None
    )


# --- ElastiCache -------------------------------------------------------------
def test_elasticache_at_rest_fires_when_disabled() -> None:
    rule = ElastiCacheAtRestEncryptionRule()
    cfg = {"at_rest_encryption_enabled": False}
    assert (
        rule.evaluate(_snap("AWS::ElastiCache::ReplicationGroup", "rg", cfg))
        is not None
    )


def test_elasticache_transit_fires_when_disabled() -> None:
    rule = ElastiCacheTransitEncryptionRule()
    cfg = {"transit_encryption_enabled": False}
    assert (
        rule.evaluate(_snap("AWS::ElastiCache::ReplicationGroup", "rg", cfg))
        is not None
    )


# --- Governance / IAM / S3 extras -------------------------------------------
def test_config_recorder_fires_when_off() -> None:
    rule = ConfigRecorderDisabledRule()
    cfg = {"recording": False, "all_supported": True}
    assert (
        rule.evaluate(
            _snap("AWS::Config::ConfigurationRecorder", "rec", cfg),
        )
        is not None
    )


def test_iam_password_policy_fires_when_short() -> None:
    rule = IamPasswordPolicyWeakRule()
    cfg = {
        "minimum_password_length": 8,
        "require_symbols": True,
        "require_numbers": True,
        "password_reuse_prevention": 24,
    }
    assert (
        rule.evaluate(_snap("AWS::IAM::PasswordPolicy", "p", cfg)) is not None
    )


def test_iam_password_policy_passes_strong() -> None:
    rule = IamPasswordPolicyWeakRule()
    cfg = {
        "minimum_password_length": 14,
        "require_symbols": True,
        "require_numbers": True,
        "password_reuse_prevention": 24,
    }
    assert rule.evaluate(_snap("AWS::IAM::PasswordPolicy", "p", cfg)) is None


def test_iam_key_age_fires_when_stale() -> None:
    rule = IamAccessKeyAgeRule()
    cfg = {"access_keys": [{"status": "Active", "age_days": 200}]}
    assert rule.evaluate(_snap("AWS::IAM::User", "u", cfg)) is not None


def test_iam_key_age_passes_inactive() -> None:
    rule = IamAccessKeyAgeRule()
    cfg = {"access_keys": [{"status": "Inactive", "age_days": 200}]}
    assert rule.evaluate(_snap("AWS::IAM::User", "u", cfg)) is None


def test_s3_versioning_fires_when_disabled() -> None:
    rule = S3VersioningDisabledRule()
    cfg = {"versioning_status": "Suspended"}
    assert rule.evaluate(_snap("AWS::S3::Bucket", "b", cfg)) is not None


def test_s3_logging_fires_when_no_target() -> None:
    rule = S3LoggingDisabledRule()
    assert rule.evaluate(_snap("AWS::S3::Bucket", "b", {})) is not None


def test_s3_logging_passes_with_target() -> None:
    rule = S3LoggingDisabledRule()
    cfg = {"logging_target_bucket": "logs-bucket"}
    assert rule.evaluate(_snap("AWS::S3::Bucket", "b", cfg)) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
