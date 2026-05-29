"""Phase 2 GCP rule pack — pass/fail coverage for the 29 new rules."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cloudguardiq.adapters.rules.gcp.cloudfunctions import (
    CloudFunctionIngressRule,
    CloudFunctionPublicInvokerRule,
)
from cloudguardiq.adapters.rules.gcp.cloudrun import (
    CloudRunIngressRule,
    CloudRunPublicInvokerRule,
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
from cloudguardiq.adapters.rules.gcp.gke_extra import (
    GkeAutoUpgradeDisabledRule,
    GkeBinaryAuthorizationRule,
    GkeWorkloadIdentityRule,
)
from cloudguardiq.adapters.rules.gcp.iam_extra import (
    IamPrimitiveRoleRule,
    IamPublicMemberRule,
    ServiceAccountKeyAgeRule,
)
from cloudguardiq.adapters.rules.gcp.kms import (
    KmsKeyPublicAccessRule,
    KmsKeyRotationRule,
)
from cloudguardiq.adapters.rules.gcp.network_extra import (
    FirewallAnyPortOpenRule,
    FirewallLoggingDisabledRule,
)
from cloudguardiq.adapters.rules.gcp.pubsub import (
    PubSubTopicCmekRule,
    PubSubTopicPublicAccessRule,
)
from cloudguardiq.adapters.rules.gcp.storage_extra import (
    BucketRetentionPolicyRule,
    BucketVersioningDisabledRule,
)
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import ResourceSnapshot


def _snap(resource_type: str, name: str, config: dict) -> ResourceSnapshot:
    return ResourceSnapshot(
        tenant_id="t",
        provider=CloudProvider.GCP,
        subscription_id="proj-123",
        resource_group="gcp-global",
        resource_type=resource_type,
        resource_name=name,
        region="us-central1",
        config=config,
        tags={},
        data_tier=DataTier.TIER1_NATIVE,
        captured_at=datetime.now(timezone.utc),
    )


# --- Cloud Functions ---------------------------------------------------------
def test_cf_ingress_fires_when_all() -> None:
    rule = CloudFunctionIngressRule()
    cfg = {"ingress_settings": "ALLOW_ALL"}
    assert (
        rule.evaluate(_snap("google.cloudfunctions.Function", "f", cfg)) is not None
    )


def test_cf_ingress_passes_when_internal() -> None:
    rule = CloudFunctionIngressRule()
    cfg = {"ingress_settings": "ALLOW_INTERNAL_ONLY"}
    assert rule.evaluate(_snap("google.cloudfunctions.Function", "f", cfg)) is None


def test_cf_public_invoker_fires() -> None:
    rule = CloudFunctionPublicInvokerRule()
    cfg = {"invoker_members": ["allUsers"]}
    assert (
        rule.evaluate(_snap("google.cloudfunctions.Function", "f", cfg)) is not None
    )


def test_cf_public_invoker_passes() -> None:
    rule = CloudFunctionPublicInvokerRule()
    cfg = {"invoker_members": ["user:dev@example.com"]}
    assert rule.evaluate(_snap("google.cloudfunctions.Function", "f", cfg)) is None


# --- Cloud Run ---------------------------------------------------------------
def test_cr_ingress_fires_when_all() -> None:
    rule = CloudRunIngressRule()
    cfg = {"ingress": "all"}
    assert rule.evaluate(_snap("google.run.Service", "s", cfg)) is not None


def test_cr_ingress_passes_when_internal() -> None:
    rule = CloudRunIngressRule()
    cfg = {"ingress": "internal"}
    assert rule.evaluate(_snap("google.run.Service", "s", cfg)) is None


def test_cr_public_invoker_fires() -> None:
    rule = CloudRunPublicInvokerRule()
    cfg = {"invoker_members": ["allAuthenticatedUsers"]}
    assert rule.evaluate(_snap("google.run.Service", "s", cfg)) is not None


def test_cr_public_invoker_passes() -> None:
    rule = CloudRunPublicInvokerRule()
    cfg = {"invoker_members": []}
    assert rule.evaluate(_snap("google.run.Service", "s", cfg)) is None


# --- KMS ---------------------------------------------------------------------
def test_kms_rotation_fires_when_too_long() -> None:
    rule = KmsKeyRotationRule()
    cfg = {"rotation_period_days": 365}
    assert rule.evaluate(_snap("google.kms.CryptoKey", "k", cfg)) is not None


def test_kms_rotation_passes_when_short() -> None:
    rule = KmsKeyRotationRule()
    cfg = {"rotation_period_days": 90}
    assert rule.evaluate(_snap("google.kms.CryptoKey", "k", cfg)) is None


def test_kms_public_access_fires() -> None:
    rule = KmsKeyPublicAccessRule()
    cfg = {"iam_bindings": [{"role": "roles/x", "members": ["allUsers"]}]}
    assert rule.evaluate(_snap("google.kms.CryptoKey", "k", cfg)) is not None


def test_kms_public_access_passes() -> None:
    rule = KmsKeyPublicAccessRule()
    cfg = {
        "iam_bindings": [
            {"role": "roles/x", "members": ["user:dev@example.com"]},
        ],
    }
    assert rule.evaluate(_snap("google.kms.CryptoKey", "k", cfg)) is None


# --- Pub/Sub -----------------------------------------------------------------
def test_pubsub_cmek_fires_when_unset() -> None:
    rule = PubSubTopicCmekRule()
    assert rule.evaluate(_snap("google.pubsub.Topic", "t", {})) is not None


def test_pubsub_cmek_passes_when_set() -> None:
    rule = PubSubTopicCmekRule()
    cfg = {"kms_key_name": "projects/p/locations/l/keyRings/r/cryptoKeys/k"}
    assert rule.evaluate(_snap("google.pubsub.Topic", "t", cfg)) is None


def test_pubsub_public_fires() -> None:
    rule = PubSubTopicPublicAccessRule()
    cfg = {
        "iam_bindings": [
            {"role": "roles/pubsub.subscriber", "members": ["allUsers"]},
        ],
    }
    assert rule.evaluate(_snap("google.pubsub.Topic", "t", cfg)) is not None


# --- DNS / Secret Manager / Artifact Registry --------------------------------
def test_dns_dnssec_fires_when_off() -> None:
    rule = DnsDnssecDisabledRule()
    cfg = {"visibility": "public", "dnssec_state": "off"}
    assert rule.evaluate(_snap("google.dns.ManagedZone", "z", cfg)) is not None


def test_dns_dnssec_passes_for_private_zone() -> None:
    rule = DnsDnssecDisabledRule()
    cfg = {"visibility": "private", "dnssec_state": "off"}
    assert rule.evaluate(_snap("google.dns.ManagedZone", "z", cfg)) is None


def test_secret_manager_cmek_fires_when_unset() -> None:
    rule = SecretManagerCmekRule()
    assert (
        rule.evaluate(_snap("google.secretmanager.Secret", "s", {})) is not None
    )


def test_artifact_registry_cmek_fires_when_unset() -> None:
    rule = ArtifactRegistryCmekRule()
    assert (
        rule.evaluate(_snap("google.artifactregistry.Repository", "r", {}))
        is not None
    )


def test_artifact_registry_public_fires() -> None:
    rule = ArtifactRegistryPublicAccessRule()
    cfg = {
        "iam_bindings": [
            {"role": "roles/artifactregistry.reader", "members": ["allUsers"]},
        ],
    }
    assert (
        rule.evaluate(_snap("google.artifactregistry.Repository", "r", cfg))
        is not None
    )


# --- IAM extras --------------------------------------------------------------
def test_iam_primitive_fires_when_owner_assigned() -> None:
    rule = IamPrimitiveRoleRule()
    cfg = {
        "bindings": [
            {"role": "roles/owner", "members": ["user:dev@example.com"]},
        ],
    }
    assert rule.evaluate(_snap("google.iam.ProjectPolicy", "p", cfg)) is not None


def test_iam_primitive_passes_when_predefined() -> None:
    rule = IamPrimitiveRoleRule()
    cfg = {
        "bindings": [
            {"role": "roles/storage.admin", "members": ["user:dev@example.com"]},
        ],
    }
    assert rule.evaluate(_snap("google.iam.ProjectPolicy", "p", cfg)) is None


def test_iam_public_member_fires() -> None:
    rule = IamPublicMemberRule()
    cfg = {"bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}
    assert rule.evaluate(_snap("google.iam.ProjectPolicy", "p", cfg)) is not None


def test_sa_key_age_fires_when_old() -> None:
    rule = ServiceAccountKeyAgeRule()
    cfg = {"user_managed_keys": [{"age_days": 120}]}
    assert (
        rule.evaluate(_snap("google.iam.ServiceAccount", "sa", cfg)) is not None
    )


def test_sa_key_age_passes_when_fresh() -> None:
    rule = ServiceAccountKeyAgeRule()
    cfg = {"user_managed_keys": [{"age_days": 30}]}
    assert rule.evaluate(_snap("google.iam.ServiceAccount", "sa", cfg)) is None


# --- Compute extras ----------------------------------------------------------
def test_shielded_vm_fires_when_features_missing() -> None:
    rule = InstanceShieldedVmRule()
    cfg = {
        "shielded_instance_config": {
            "enable_secure_boot": False,
            "enable_vtpm": True,
            "enable_integrity_monitoring": True,
        },
    }
    assert rule.evaluate(_snap("google.compute.Instance", "vm", cfg)) is not None


def test_shielded_vm_passes_when_all_enabled() -> None:
    rule = InstanceShieldedVmRule()
    cfg = {
        "shielded_instance_config": {
            "enable_secure_boot": True,
            "enable_vtpm": True,
            "enable_integrity_monitoring": True,
        },
    }
    assert rule.evaluate(_snap("google.compute.Instance", "vm", cfg)) is None


def test_oslogin_fires_when_disabled() -> None:
    rule = InstanceOsLoginDisabledRule()
    cfg = {"enable_oslogin": "FALSE"}
    assert rule.evaluate(_snap("google.compute.Instance", "vm", cfg)) is not None


def test_default_sa_fires_when_default() -> None:
    rule = InstanceDefaultServiceAccountRule()
    cfg = {
        "service_account_emails": [
            "1234-compute@developer.gserviceaccount.com",
        ],
    }
    assert rule.evaluate(_snap("google.compute.Instance", "vm", cfg)) is not None


def test_default_sa_passes_when_custom() -> None:
    rule = InstanceDefaultServiceAccountRule()
    cfg = {"service_account_emails": ["app@proj.iam.gserviceaccount.com"]}
    assert rule.evaluate(_snap("google.compute.Instance", "vm", cfg)) is None


# --- GKE extras --------------------------------------------------------------
def test_gke_workload_identity_fires_when_unset() -> None:
    rule = GkeWorkloadIdentityRule()
    assert rule.evaluate(_snap("google.container.Cluster", "c", {})) is not None


def test_gke_workload_identity_passes_when_set() -> None:
    rule = GkeWorkloadIdentityRule()
    cfg = {"workload_identity_pool": "proj.svc.id.goog"}
    assert rule.evaluate(_snap("google.container.Cluster", "c", cfg)) is None


def test_gke_auto_upgrade_fires_when_disabled() -> None:
    rule = GkeAutoUpgradeDisabledRule()
    cfg = {"auto_upgrade": False}
    assert rule.evaluate(_snap("google.container.NodePool", "np", cfg)) is not None


def test_gke_binary_auth_fires_when_disabled() -> None:
    rule = GkeBinaryAuthorizationRule()
    cfg = {"binary_authorization_mode": "DISABLED"}
    assert rule.evaluate(_snap("google.container.Cluster", "c", cfg)) is not None


# --- Storage extras ----------------------------------------------------------
def test_bucket_versioning_fires_when_disabled() -> None:
    rule = BucketVersioningDisabledRule()
    cfg = {"versioning_enabled": False}
    assert rule.evaluate(_snap("google.storage.Bucket", "b", cfg)) is not None


def test_bucket_retention_fires_when_unlocked() -> None:
    rule = BucketRetentionPolicyRule()
    cfg = {"retention_policy": {"is_locked": False, "retention_period_days": 30}}
    assert rule.evaluate(_snap("google.storage.Bucket", "b", cfg)) is not None


def test_bucket_retention_passes_when_locked() -> None:
    rule = BucketRetentionPolicyRule()
    cfg = {"retention_policy": {"is_locked": True, "retention_period_days": 365}}
    assert rule.evaluate(_snap("google.storage.Bucket", "b", cfg)) is None


# --- Network extras ----------------------------------------------------------
def test_firewall_any_port_fires_when_open() -> None:
    rule = FirewallAnyPortOpenRule()
    cfg = {
        "direction": "INGRESS",
        "source_ranges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "all"}],
    }
    assert rule.evaluate(_snap("google.compute.Firewall", "fw", cfg)) is not None


def test_firewall_any_port_passes_when_scoped() -> None:
    rule = FirewallAnyPortOpenRule()
    cfg = {
        "direction": "INGRESS",
        "source_ranges": ["10.0.0.0/8"],
        "allowed": [{"IPProtocol": "all"}],
    }
    assert rule.evaluate(_snap("google.compute.Firewall", "fw", cfg)) is None


def test_firewall_logging_fires_when_off() -> None:
    rule = FirewallLoggingDisabledRule()
    cfg = {"log_config_enabled": False}
    assert rule.evaluate(_snap("google.compute.Firewall", "fw", cfg)) is not None


# --- Data services -----------------------------------------------------------
def test_spanner_cmek_fires_when_unset() -> None:
    rule = SpannerCmekRule()
    assert rule.evaluate(_snap("google.spanner.Database", "d", {})) is not None


def test_memorystore_auth_fires_when_disabled() -> None:
    rule = MemorystoreAuthDisabledRule()
    cfg = {"auth_enabled": False}
    assert rule.evaluate(_snap("google.redis.Instance", "r", cfg)) is not None


def test_memorystore_transit_fires_when_disabled() -> None:
    rule = MemorystoreTransitEncryptionRule()
    cfg = {"transit_encryption_mode": "DISABLED"}
    assert rule.evaluate(_snap("google.redis.Instance", "r", cfg)) is not None


def test_bq_partition_expiry_fires_when_unset() -> None:
    rule = BigQueryTablePartitionExpiryRule()
    cfg = {"time_partitioning": {"type": "DAY"}}
    assert rule.evaluate(_snap("google.bigquery.Table", "t", cfg)) is not None


def test_bq_partition_expiry_passes_when_set() -> None:
    rule = BigQueryTablePartitionExpiryRule()
    cfg = {"time_partitioning": {"type": "DAY", "expiration_ms": 7776000000}}
    assert rule.evaluate(_snap("google.bigquery.Table", "t", cfg)) is None


def test_bq_partition_expiry_skips_non_partitioned() -> None:
    rule = BigQueryTablePartitionExpiryRule()
    assert rule.evaluate(_snap("google.bigquery.Table", "t", {})) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
