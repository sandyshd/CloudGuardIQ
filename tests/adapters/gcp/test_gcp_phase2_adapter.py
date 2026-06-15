"""Phase-2 GCP adapter coverage tests.

Exercises the extended resource collectors (BigQuery, GKE, Cloud SQL,
Cloud Run, KMS, Pub/Sub, Secret Manager, and friends) by injecting fake
client objects via the per-service client helpers. The google client
libraries are never imported -- the fakes mimic the minimal surface each
collector reads, mirroring the AWS phase-2 test strategy.
"""

from __future__ import annotations

from types import SimpleNamespace as Ns
from typing import Any

import pytest

from cloudguardiq.adapters.gcp.adapter import GCPAdapter
from cloudguardiq.policy.engine import PolicyEngine

PROJECT = "proj-123"


def _ns(**kw: Any) -> Ns:
    return Ns(**kw)


# --------------------------------------------------------------------------
# Fake clients -- one per service helper. Each returns deliberately insecure
# resources so the corresponding policy rules fire.
# --------------------------------------------------------------------------


class _FakeBigQuery:
    def list_datasets(self) -> list[Any]:
        return [_ns(dataset_id="public_ds")]

    def get_dataset(self, ref: Any) -> Any:
        entry = _ns(
            role="READER",
            entity_type="specialGroup",
            entity_id="allAuthenticatedUsers",
        )
        return _ns(
            dataset_id="public_ds",
            location="US",
            access_entries=[entry],
            default_encryption_configuration=None,
        )

    def list_tables(self, ref: Any) -> list[Any]:
        return [_ns(table_id="unpartitioned")]

    def get_table(self, ref: Any) -> Any:
        return _ns(table_id="unpartitioned", location="US", time_partitioning=None)


class _FakeFunctions:
    def list_functions(self, parent: str) -> list[Any]:
        return [
            _ns(
                name=f"projects/{PROJECT}/locations/us-central1/functions/f1",
                service_config=_ns(ingress_settings=_ns(name="ALLOW_ALL")),
            )
        ]

    def get_iam_policy(self, request: dict[str, Any]) -> Any:
        return _ns(
            bindings=[_ns(role="roles/cloudfunctions.invoker", members=["allUsers"])]
        )


class _FakeRun:
    def list_services(self, parent: str) -> list[Any]:
        return [
            _ns(
                name=f"projects/{PROJECT}/locations/us-central1/services/svc1",
                ingress=_ns(name="INGRESS_TRAFFIC_ALL"),
            )
        ]

    def get_iam_policy(self, request: dict[str, Any]) -> Any:
        return _ns(bindings=[_ns(role="roles/run.invoker", members=["allUsers"])])


class _FakeSqlInstances:
    def list(self, project: str) -> Any:
        return _ns(
            execute=lambda: {
                "items": [
                    {
                        "name": "db1",
                        "region": "us-central1",
                        "settings": {
                            "ipConfiguration": {
                                "ipv4Enabled": True,
                                "requireSsl": False,
                            },
                            "backupConfiguration": {"enabled": False},
                        },
                    }
                ]
            }
        )


class _FakeSqlAdmin:
    def instances(self) -> _FakeSqlInstances:
        return _FakeSqlInstances()


class _FakeSpannerDatabase:
    name = f"projects/{PROJECT}/instances/i1/databases/d1"
    encryption_config = None


class _FakeSpannerInstance:
    name = f"projects/{PROJECT}/instances/i1"

    def list_databases(self) -> list[Any]:
        return [_FakeSpannerDatabase()]


class _FakeSpanner:
    def list_instances(self) -> list[Any]:
        return [_FakeSpannerInstance()]


class _FakeRedis:
    def list_instances(self, parent: str) -> list[Any]:
        return [
            _ns(
                name=f"projects/{PROJECT}/locations/us-central1/instances/r1",
                auth_enabled=False,
                transit_encryption_mode=_ns(name="DISABLED"),
            )
        ]


class _FakeDns:
    def list_zones(self) -> list[Any]:
        return [_ns(name="zone1", visibility="public", dnssec_state="off")]


class _FakeSecrets:
    def list_secrets(self, request: dict[str, Any]) -> list[Any]:
        return [
            _ns(
                name=f"projects/{PROJECT}/secrets/s1",
                customer_managed_encryption=None,
            )
        ]


class _FakeArtifactRegistry:
    def list_repositories(self, parent: str) -> list[Any]:
        return [
            _ns(
                name=f"projects/{PROJECT}/locations/us-central1/repositories/repo1",
                kms_key_name="",
            )
        ]

    def get_iam_policy(self, request: dict[str, Any]) -> Any:
        return _ns(bindings=[_ns(role="roles/artifactregistry.reader", members=["allUsers"])])


class _FakeContainer:
    def list_clusters(self, parent: str) -> Any:
        node_pool = _ns(name="np1", management=_ns(auto_upgrade=False))
        cluster = _ns(
            name="cluster1",
            location="us-central1",
            private_cluster_config=_ns(enable_private_nodes=False),
            logging_service="none",
            network_policy=_ns(enabled=False),
            workload_identity_config=None,
            binary_authorization=_ns(evaluation_mode="DISABLED"),
            node_pools=[node_pool],
        )
        return _ns(clusters=[cluster])


class _FakeKmsKey:
    def __init__(self) -> None:
        self.name = f"projects/{PROJECT}/locations/global/keyRings/kr1/cryptoKeys/k1"
        self.rotation_period = None


class _FakeKms:
    def list_key_rings(self, parent: str) -> list[Any]:
        return [_ns(name=f"projects/{PROJECT}/locations/global/keyRings/kr1")]

    def list_crypto_keys(self, parent: str) -> list[Any]:
        return [_FakeKmsKey()]

    def get_iam_policy(self, request: dict[str, Any]) -> Any:
        return _ns(bindings=[_ns(role="roles/cloudkms.cryptoKeyDecrypter", members=["allUsers"])])


class _FakeLoggingConfig:
    def list_sinks(self, parent: str) -> list[Any]:
        return [_ns(name="sink1", filter="")]

    def list_buckets(self, parent: str) -> list[Any]:
        return [
            _ns(
                name=f"projects/{PROJECT}/locations/global/buckets/b1",
                retention_days=7,
            )
        ]


class _FakePubsub:
    def list_topics(self, request: dict[str, Any]) -> list[Any]:
        return [_ns(name=f"projects/{PROJECT}/topics/t1", kms_key_name="")]

    def get_iam_policy(self, request: dict[str, Any]) -> Any:
        return _ns(bindings=[_ns(role="roles/pubsub.subscriber", members=["allUsers"])])


class _FakeResourceManager:
    def get_iam_policy(self, request: dict[str, Any]) -> Any:
        return _ns(
            bindings=[
                _ns(role="roles/owner", members=["user:a@b.com", "allUsers"]),
            ]
        )


def _wire(adapter: GCPAdapter) -> None:
    adapter._bigquery_client = lambda: _FakeBigQuery()  # type: ignore[method-assign]
    adapter._functions_client = lambda: _FakeFunctions()  # type: ignore[method-assign]
    adapter._run_client = lambda: _FakeRun()  # type: ignore[method-assign]
    adapter._sql_admin_client = lambda: _FakeSqlAdmin()  # type: ignore[method-assign]
    adapter._spanner_client = lambda: _FakeSpanner()  # type: ignore[method-assign]
    adapter._redis_client = lambda: _FakeRedis()  # type: ignore[method-assign]
    adapter._dns_client = lambda: _FakeDns()  # type: ignore[method-assign]
    adapter._secrets_client = lambda: _FakeSecrets()  # type: ignore[method-assign]
    adapter._artifactregistry_client = lambda: _FakeArtifactRegistry()  # type: ignore[method-assign]
    adapter._container_client = lambda: _FakeContainer()  # type: ignore[method-assign]
    adapter._kms_client = lambda: _FakeKms()  # type: ignore[method-assign]
    adapter._logging_config_client = lambda: _FakeLoggingConfig()  # type: ignore[method-assign]
    adapter._pubsub_client = lambda: _FakePubsub()  # type: ignore[method-assign]
    adapter._resource_manager_client = lambda: _FakeResourceManager()  # type: ignore[method-assign]


@pytest.fixture()
def adapter() -> GCPAdapter:
    a = GCPAdapter(project_id=PROJECT)
    _wire(a)
    return a


def _collect_phase2(adapter: GCPAdapter) -> list[Any]:
    return [
        *adapter._scan_bigquery_datasets(),
        *adapter._scan_cloud_functions(),
        *adapter._scan_cloud_run(),
        *adapter._scan_cloud_sql(),
        *adapter._scan_spanner(),
        *adapter._scan_redis(),
        *adapter._scan_dns_zones(),
        *adapter._scan_secrets(),
        *adapter._scan_artifact_registry(),
        *adapter._scan_gke_clusters(),
        *adapter._scan_kms_keys(),
        *adapter._scan_logging(),
        *adapter._scan_pubsub_topics(),
        *adapter._scan_project_iam(),
    ]


def test_phase2_collectors_emit_expected_types(adapter: GCPAdapter) -> None:
    snaps = _collect_phase2(adapter)
    types = {s.resource_type for s in snaps}
    expected = {
        "google.bigquery.Dataset",
        "google.bigquery.Table",
        "google.cloudfunctions.Function",
        "google.run.Service",
        "google.sql.Instance",
        "google.spanner.Database",
        "google.redis.Instance",
        "google.dns.ManagedZone",
        "google.secretmanager.Secret",
        "google.artifactregistry.Repository",
        "google.container.Cluster",
        "google.container.NodePool",
        "google.kms.CryptoKey",
        "google.logging.Project",
        "google.logging.LogBucket",
        "google.pubsub.Topic",
        "google.iam.ProjectPolicy",
    }
    missing = expected - types
    assert not missing, f"missing resource types: {sorted(missing)}"


def test_phase2_snapshots_produce_findings(adapter: GCPAdapter) -> None:
    snaps = _collect_phase2(adapter)
    findings = PolicyEngine().evaluate(snaps)
    fired = {f.rule_id for f in findings}
    # every phase-2 resource type should trip at least one rule
    must_fire = {
        "GCP-BQ-001",
        "GCP-CF-001",
        "GCP-CR-001",
        "GCP-SQL-002",
        "GCP-MEM-001",
        "GCP-AR-001",
        "GCP-GKE-001",
        "GCP-GKE-005",
        "GCP-KMS-001",
        "GCP-PS-001",
        "GCP-IAM-002",
        "GCP-SEC-001",
    }
    missing = must_fire - fired
    assert not missing, f"expected rules did not fire: {sorted(missing)}"


def test_phase2_validates_snapshots(adapter: GCPAdapter) -> None:
    for snap in _collect_phase2(adapter):
        assert snap.subscription_id == PROJECT
        assert snap.resource_name
        assert snap.region
        assert snap.data_tier is not None
