"""CloudGuardIQ — AWS rule registry.

Kept separate from the Azure ``RULE_REGISTRY`` so each cloud provider's
rule pack can evolve independently. The ``PolicyEngine`` only evaluates
rules whose ``resource_types`` match the snapshot, so it is safe to
combine both registries — see
:func:`cloudguardiq.adapters.rules.aws.registry.combined_registry`.
"""

from __future__ import annotations

from collections.abc import Sequence

from cloudguardiq.adapters.rules.aws.apigateway import (
    ApiGatewayLoggingDisabledRule,
    ApiGatewayNoWafRule,
)
from cloudguardiq.adapters.rules.aws.cloudtrail import (
    CloudTrailLogFileValidationRule,
    CloudTrailMultiRegionRule,
    CloudTrailNotLoggingRule,
)
from cloudguardiq.adapters.rules.aws.cloudwatch import (
    LogGroupKmsKeyRule,
    LogGroupRetentionRule,
)
from cloudguardiq.adapters.rules.aws.dynamodb import (
    DynamoDbCmekEncryptionRule,
    DynamoDbPitrDisabledRule,
)
from cloudguardiq.adapters.rules.aws.ec2 import (
    EbsEncryptionRule,
    InstancePublicIpRule,
    UnattachedEbsVolumeRule,
)
from cloudguardiq.adapters.rules.aws.ecr import (
    EcrScanOnPushRule,
    EcrTagImmutabilityRule,
)
from cloudguardiq.adapters.rules.aws.eks import (
    EksControlPlaneLoggingRule,
    EksPublicEndpointRule,
    EksSecretsEncryptionRule,
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
from cloudguardiq.adapters.rules.aws.finops import UnattachedEipRule
from cloudguardiq.adapters.rules.aws.governance import (
    ConfigRecorderDisabledRule,
    IamAccessKeyAgeRule,
    IamPasswordPolicyWeakRule,
    S3LoggingDisabledRule,
    S3VersioningDisabledRule,
)
from cloudguardiq.adapters.rules.aws.iam import (
    IamUserNoMfaRule,
    RootAccessKeysRule,
)
from cloudguardiq.adapters.rules.aws.kms import KmsKeyRotationRule
from cloudguardiq.adapters.rules.aws.lambda_ import (
    LambdaEnvVarKmsKeyRule,
    LambdaOutdatedRuntimeRule,
    LambdaPublicFunctionUrlRule,
)
from cloudguardiq.adapters.rules.aws.messaging import (
    SnsTopicEncryptionRule,
    SnsTopicPublicAccessRule,
    SqsQueueEncryptionRule,
    SqsQueuePublicAccessRule,
)
from cloudguardiq.adapters.rules.aws.rds import (
    RdsBackupRetentionRule,
    RdsPubliclyAccessibleRule,
    RdsStorageEncryptionRule,
)
from cloudguardiq.adapters.rules.aws.s3 import (
    S3BucketEncryptionRule,
    S3PublicAccessBlockRule,
    S3PublicAclRule,
)
from cloudguardiq.adapters.rules.aws.secrets_acm import (
    AcmCertificateExpiringRule,
    SecretRotationDisabledRule,
)
from cloudguardiq.adapters.rules.aws.security_group import (
    RDPOpenToInternetRule,
    SSHOpenToInternetRule,
)
from cloudguardiq.adapters.rules.aws.vpc import (
    DefaultSecurityGroupOpenRule,
    VpcFlowLogsDisabledRule,
)

AWS_RULE_REGISTRY: list = [
    # S3 (3)
    S3PublicAclRule(),
    S3PublicAccessBlockRule(),
    S3BucketEncryptionRule(),
    # EC2 / EBS (3)
    EbsEncryptionRule(),
    InstancePublicIpRule(),
    UnattachedEbsVolumeRule(),
    # Security groups (2)
    SSHOpenToInternetRule(),
    RDPOpenToInternetRule(),
    # IAM (2)
    RootAccessKeysRule(),
    IamUserNoMfaRule(),
    # FinOps (1)
    UnattachedEipRule(),
    # RDS (3)
    RdsStorageEncryptionRule(),
    RdsPubliclyAccessibleRule(),
    RdsBackupRetentionRule(),
    # Lambda (3)
    LambdaEnvVarKmsKeyRule(),
    LambdaPublicFunctionUrlRule(),
    LambdaOutdatedRuntimeRule(),
    # CloudTrail (3)
    CloudTrailMultiRegionRule(),
    CloudTrailNotLoggingRule(),
    CloudTrailLogFileValidationRule(),
    # EKS (3)
    EksPublicEndpointRule(),
    EksControlPlaneLoggingRule(),
    EksSecretsEncryptionRule(),
    # KMS (1)
    KmsKeyRotationRule(),
    # DynamoDB (2)
    DynamoDbCmekEncryptionRule(),
    DynamoDbPitrDisabledRule(),
    # SNS / SQS (4)
    SnsTopicEncryptionRule(),
    SnsTopicPublicAccessRule(),
    SqsQueueEncryptionRule(),
    SqsQueuePublicAccessRule(),
    # ELB / ALB (3)
    ElbHttpListenerRule(),
    ElbAccessLogsDisabledRule(),
    ElbDeletionProtectionRule(),
    # VPC (2)
    VpcFlowLogsDisabledRule(),
    DefaultSecurityGroupOpenRule(),
    # CloudWatch Logs (2)
    LogGroupRetentionRule(),
    LogGroupKmsKeyRule(),
    # ECR (2)
    EcrScanOnPushRule(),
    EcrTagImmutabilityRule(),
    # API Gateway (2)
    ApiGatewayLoggingDisabledRule(),
    ApiGatewayNoWafRule(),
    # Secrets Manager + ACM (2)
    SecretRotationDisabledRule(),
    AcmCertificateExpiringRule(),
    # ElastiCache (2)
    ElastiCacheAtRestEncryptionRule(),
    ElastiCacheTransitEncryptionRule(),
    # Governance / IAM extras / S3 extras (5)
    ConfigRecorderDisabledRule(),
    IamPasswordPolicyWeakRule(),
    IamAccessKeyAgeRule(),
    S3VersioningDisabledRule(),
    S3LoggingDisabledRule(),
]


def combined_registry(*registries: Sequence) -> list:
    """Return a flat list combining one or more rule registries."""
    out: list = []
    for reg in registries:
        out.extend(reg)
    return out
