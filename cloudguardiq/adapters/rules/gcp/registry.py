"""CloudGuardIQ -- GCP rule registry.

Provides ``GCP_RULE_REGISTRY``, a flat list of instantiated PolicyRule
objects. The list is consumed by ``PolicyEngine`` discovery and can be
combined with other registries via ``combined_registry``.
"""

from __future__ import annotations

from cloudguardiq.adapters.rules.gcp.bigquery import (
    BigQueryDatasetCmekRule,
    BigQueryDatasetPublicAccessRule,
)
from cloudguardiq.adapters.rules.gcp.cloudfunctions import (
    CloudFunctionIngressRule,
    CloudFunctionPublicInvokerRule,
)
from cloudguardiq.adapters.rules.gcp.cloudrun import (
    CloudRunIngressRule,
    CloudRunPublicInvokerRule,
)
from cloudguardiq.adapters.rules.gcp.cloudsql import (
    CloudSqlBackupDisabledRule,
    CloudSqlPublicIpRule,
    CloudSqlRequireSslRule,
)
from cloudguardiq.adapters.rules.gcp.compute import (
    DiskCmekEncryptionRule,
    InstancePublicIpRule,
    UnattachedDiskRule,
)
from cloudguardiq.adapters.rules.gcp.compute_extra import (
    InstanceDefaultServiceAccountRule,
    InstanceOsLoginDisabledRule,
    InstanceShieldedVmRule,
)
from cloudguardiq.adapters.rules.gcp.data_services import (
    BigQueryTablePartitionExpiryRule,
    MemorystoreAuthDisabledRule,
    MemorystoreTransitEncryptionRule,
    SpannerCmekRule,
)
from cloudguardiq.adapters.rules.gcp.dns_secrets import (
    ArtifactRegistryCmekRule,
    ArtifactRegistryPublicAccessRule,
    DnsDnssecDisabledRule,
    SecretManagerCmekRule,
)
from cloudguardiq.adapters.rules.gcp.gke import (
    GkeLoggingDisabledRule,
    GkeNetworkPolicyRule,
    GkePrivateClusterRule,
)
from cloudguardiq.adapters.rules.gcp.gke_extra import (
    GkeAutoUpgradeDisabledRule,
    GkeBinaryAuthorizationRule,
    GkeWorkloadIdentityRule,
)
from cloudguardiq.adapters.rules.gcp.iam import ServiceAccountUserManagedKeyRule
from cloudguardiq.adapters.rules.gcp.iam_extra import (
    IamPrimitiveRoleRule,
    IamPublicMemberRule,
    ServiceAccountKeyAgeRule,
)
from cloudguardiq.adapters.rules.gcp.kms import (
    KmsKeyPublicAccessRule,
    KmsKeyRotationRule,
)
from cloudguardiq.adapters.rules.gcp.logging import (
    LoggingRetentionRule,
    LoggingSinkMissingRule,
)
from cloudguardiq.adapters.rules.gcp.network import (
    FirewallRdpOpenRule,
    FirewallSshOpenRule,
)
from cloudguardiq.adapters.rules.gcp.network_extra import (
    FirewallAnyPortOpenRule,
    FirewallLoggingDisabledRule,
)
from cloudguardiq.adapters.rules.gcp.pubsub import (
    PubSubTopicCmekRule,
    PubSubTopicPublicAccessRule,
)
from cloudguardiq.adapters.rules.gcp.storage import (
    BucketPublicAccessRule,
    BucketUniformAccessRule,
)
from cloudguardiq.adapters.rules.gcp.storage_extra import (
    BucketRetentionPolicyRule,
    BucketVersioningDisabledRule,
)

GCP_RULE_REGISTRY: list = [
    InstancePublicIpRule(),
    DiskCmekEncryptionRule(),
    UnattachedDiskRule(),
    BucketPublicAccessRule(),
    BucketUniformAccessRule(),
    ServiceAccountUserManagedKeyRule(),
    FirewallSshOpenRule(),
    FirewallRdpOpenRule(),
    # Cloud SQL (3)
    CloudSqlPublicIpRule(),
    CloudSqlBackupDisabledRule(),
    CloudSqlRequireSslRule(),
    # GKE (3)
    GkePrivateClusterRule(),
    GkeLoggingDisabledRule(),
    GkeNetworkPolicyRule(),
    # BigQuery (2)
    BigQueryDatasetPublicAccessRule(),
    BigQueryDatasetCmekRule(),
    # Cloud Logging (2)
    LoggingSinkMissingRule(),
    LoggingRetentionRule(),
    # Cloud Functions (2)
    CloudFunctionIngressRule(),
    CloudFunctionPublicInvokerRule(),
    # Cloud Run (2)
    CloudRunIngressRule(),
    CloudRunPublicInvokerRule(),
    # KMS (2)
    KmsKeyRotationRule(),
    KmsKeyPublicAccessRule(),
    # Pub/Sub (2)
    PubSubTopicCmekRule(),
    PubSubTopicPublicAccessRule(),
    # DNS / Secret Manager / Artifact Registry (4)
    DnsDnssecDisabledRule(),
    SecretManagerCmekRule(),
    ArtifactRegistryCmekRule(),
    ArtifactRegistryPublicAccessRule(),
    # IAM extras (3)
    IamPrimitiveRoleRule(),
    IamPublicMemberRule(),
    ServiceAccountKeyAgeRule(),
    # Compute extras (3)
    InstanceShieldedVmRule(),
    InstanceOsLoginDisabledRule(),
    InstanceDefaultServiceAccountRule(),
    # GKE extras (3)
    GkeWorkloadIdentityRule(),
    GkeAutoUpgradeDisabledRule(),
    GkeBinaryAuthorizationRule(),
    # Storage extras (2)
    BucketVersioningDisabledRule(),
    BucketRetentionPolicyRule(),
    # Network extras (2)
    FirewallAnyPortOpenRule(),
    FirewallLoggingDisabledRule(),
    # Data services (4)
    SpannerCmekRule(),
    MemorystoreAuthDisabledRule(),
    MemorystoreTransitEncryptionRule(),
    BigQueryTablePartitionExpiryRule(),
]

__all__ = ["GCP_RULE_REGISTRY"]
