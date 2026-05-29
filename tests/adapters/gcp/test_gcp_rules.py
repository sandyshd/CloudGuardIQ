"""Unit tests for the GCP rule pack."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cloudguardiq.adapters.rules.gcp.compute import (
    DiskCmekEncryptionRule,
    InstancePublicIpRule,
    UnattachedDiskRule,
)
from cloudguardiq.adapters.rules.gcp.iam import ServiceAccountUserManagedKeyRule
from cloudguardiq.adapters.rules.gcp.network import (
    FirewallRdpOpenRule,
    FirewallSshOpenRule,
)
from cloudguardiq.adapters.rules.gcp.registry import GCP_RULE_REGISTRY
from cloudguardiq.adapters.rules.gcp.storage import (
    BucketPublicAccessRule,
    BucketUniformAccessRule,
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


def test_registry_has_expected_rule_count() -> None:
    """Sanity: rule pack ships 47 rules."""
    assert len(GCP_RULE_REGISTRY) == 47


def test_instance_public_ip_rule_fires_when_external_ip_present() -> None:
    rule = InstancePublicIpRule()
    finding = rule.evaluate(
        _snap("google.compute.Instance", "vm-1", {"external_ips": ["34.1.2.3"]})
    )
    assert finding is not None
    assert finding.rule_id == "GCP-CE-001"


def test_instance_public_ip_rule_passes_when_internal_only() -> None:
    rule = InstancePublicIpRule()
    assert rule.evaluate(
        _snap("google.compute.Instance", "vm-2", {"external_ips": []})
    ) is None


def test_disk_cmek_rule_fires_when_not_cmek() -> None:
    rule = DiskCmekEncryptionRule()
    finding = rule.evaluate(
        _snap("google.compute.Disk", "d-1", {"cmek_encrypted": False, "users": ["v"]})
    )
    assert finding is not None
    assert finding.rule_id == "GCP-CE-002"


def test_disk_cmek_rule_passes_when_cmek() -> None:
    rule = DiskCmekEncryptionRule()
    assert rule.evaluate(
        _snap("google.compute.Disk", "d-2", {"cmek_encrypted": True})
    ) is None


def test_unattached_disk_rule_fires_when_no_users() -> None:
    rule = UnattachedDiskRule()
    finding = rule.evaluate(
        _snap("google.compute.Disk", "d-3", {"users": [], "size_gb": 500})
    )
    assert finding is not None
    assert finding.rule_id == "GCP-CE-003"


def test_unattached_disk_rule_passes_when_attached() -> None:
    rule = UnattachedDiskRule()
    assert rule.evaluate(
        _snap("google.compute.Disk", "d-4", {"users": ["vm"], "size_gb": 100})
    ) is None


def test_bucket_public_rule_fires_when_public_iam() -> None:
    rule = BucketPublicAccessRule()
    finding = rule.evaluate(
        _snap(
            "google.storage.Bucket",
            "my-bucket",
            {"public_iam_member": True, "uniform_bucket_level_access": True},
        )
    )
    assert finding is not None
    assert finding.rule_id == "GCP-GCS-001"


def test_bucket_uniform_rule_fires_when_legacy_acls() -> None:
    rule = BucketUniformAccessRule()
    finding = rule.evaluate(
        _snap(
            "google.storage.Bucket",
            "legacy-bucket",
            {"uniform_bucket_level_access": False},
        )
    )
    assert finding is not None
    assert finding.rule_id == "GCP-GCS-002"


def test_service_account_user_managed_keys_rule_fires() -> None:
    rule = ServiceAccountUserManagedKeyRule()
    finding = rule.evaluate(
        _snap(
            "google.iam.ServiceAccount",
            "sa@proj.iam",
            {"user_managed_keys": 2, "disabled": False},
        )
    )
    assert finding is not None
    assert finding.rule_id == "GCP-IAM-001"


@pytest.mark.parametrize(
    "rule_cls,port",
    [(FirewallSshOpenRule, 22), (FirewallRdpOpenRule, 3389)],
)
def test_firewall_open_rules_fire_for_world_ingress(rule_cls, port) -> None:
    rule = rule_cls()
    finding = rule.evaluate(
        _snap(
            "google.compute.Firewall",
            f"allow-{port}",
            {
                "direction": "INGRESS",
                "disabled": False,
                "source_ranges": ["0.0.0.0/0"],
                "allowed": [{"protocol": "tcp", "ports": [str(port)]}],
            },
        )
    )
    assert finding is not None


@pytest.mark.parametrize(
    "rule_cls,port",
    [(FirewallSshOpenRule, 22), (FirewallRdpOpenRule, 3389)],
)
def test_firewall_open_rules_pass_for_restricted_range(rule_cls, port) -> None:
    rule = rule_cls()
    assert (
        rule.evaluate(
            _snap(
                "google.compute.Firewall",
                f"allow-{port}-vpn",
                {
                    "direction": "INGRESS",
                    "disabled": False,
                    "source_ranges": ["10.0.0.0/8"],
                    "allowed": [{"protocol": "tcp", "ports": [str(port)]}],
                },
            )
        )
        is None
    )


def test_engine_auto_discovers_gcp_rules() -> None:
    """PolicyEngine should pick up all GCP rules via walk_packages."""
    from cloudguardiq.policy.engine import PolicyEngine

    engine = PolicyEngine()
    rule_ids = {r.rule_id for r in engine._native_rules if r.rule_id.startswith("GCP-")}
    assert rule_ids == {
        "GCP-CE-001",
        "GCP-CE-002",
        "GCP-CE-003",
        "GCP-CE-004",
        "GCP-CE-005",
        "GCP-CE-006",
        "GCP-GCS-001",
        "GCP-GCS-002",
        "GCP-GCS-003",
        "GCP-GCS-004",
        "GCP-IAM-001",
        "GCP-IAM-002",
        "GCP-IAM-003",
        "GCP-IAM-004",
        "GCP-NET-001",
        "GCP-NET-002",
        "GCP-NET-003",
        "GCP-NET-004",
        "GCP-SQL-001",
        "GCP-SQL-002",
        "GCP-SQL-003",
        "GCP-GKE-001",
        "GCP-GKE-002",
        "GCP-GKE-003",
        "GCP-GKE-004",
        "GCP-GKE-005",
        "GCP-GKE-006",
        "GCP-BQ-001",
        "GCP-BQ-002",
        "GCP-BQ-003",
        "GCP-LOG-001",
        "GCP-LOG-002",
        "GCP-CF-001",
        "GCP-CF-002",
        "GCP-CR-001",
        "GCP-CR-002",
        "GCP-KMS-001",
        "GCP-KMS-002",
        "GCP-PS-001",
        "GCP-PS-002",
        "GCP-DNS-001",
        "GCP-SEC-001",
        "GCP-AR-001",
        "GCP-AR-002",
        "GCP-SPN-001",
        "GCP-MEM-001",
        "GCP-MEM-002",
    }
