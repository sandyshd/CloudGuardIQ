"""CloudGuardIQ -- GCP read-only adapter (Tier-1 native scanning).

Enumerates a curated set of GCP resources via the official ``google-cloud-*``
client libraries and emits ``ResourceSnapshot`` objects that the
cloud-agnostic ``PolicyEngine`` plus ``GCP_RULE_REGISTRY`` can evaluate.

The google client libraries are imported lazily so the rest of CloudGuardIQ
(which is Azure-first today) does not require the optional ``[gcp]`` extra
to be installed.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from cloudguardiq.adapters.base import AdapterBase
from cloudguardiq.adapters.gcp.gcp_policy_compliance_adapter import (
    GCPPolicyComplianceAdapter,
)
from cloudguardiq.adapters.pricing import gcp_persistent_disk_monthly_usd
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

logger = logging.getLogger(__name__)


def _require_google() -> None:
    """Import the google client libraries lazily; raise a friendly error
    when the optional ``[gcp]`` extra is not installed."""
    try:
        import google.cloud.compute_v1  # noqa: F401
        import google.cloud.storage  # noqa: F401
    except ImportError as exc:  # pragma: no cover - guarded path
        raise RuntimeError(
            "GCPAdapter requires the optional [gcp] extra. "
            "Install with: pip install 'cloudguardiq[gcp]'"
        ) from exc


class GCPAdapter(AdapterBase):
    """Read-only GCP adapter (Tier-1 native scanning).

    Args:
        project_id: GCP project id. Populated into
            ``ResourceSnapshot.subscription_id`` so the cloud-agnostic
            data model stays consistent.
        credentials: Optional pre-built ``google.auth.credentials.Credentials``.
            When omitted, Application Default Credentials are used.
    """

    PROVIDER = CloudProvider.GCP

    def __init__(
        self,
        project_id: str,
        credentials: Any | None = None,
    ) -> None:
        self.project_id = project_id
        self._credentials = credentials
        self._policy_adapter = GCPPolicyComplianceAdapter(
            project_id=project_id,
            credentials=credentials,
        )
        self._policy_findings: list[FindingResult] = []

    # ------------------------------------------------------------------
    # Client helpers
    # ------------------------------------------------------------------

    def _compute_instances_client(self) -> Any:
        from google.cloud import compute_v1
        return compute_v1.InstancesClient(credentials=self._credentials)

    def _compute_disks_client(self) -> Any:
        from google.cloud import compute_v1
        return compute_v1.DisksClient(credentials=self._credentials)

    def _compute_firewalls_client(self) -> Any:
        from google.cloud import compute_v1
        return compute_v1.FirewallsClient(credentials=self._credentials)

    def _storage_client(self) -> Any:
        from google.cloud import storage
        return storage.Client(
            project=self.project_id,
            credentials=self._credentials,
        )

    def _iam_admin_client(self) -> Any:
        from google.cloud import iam_admin_v1
        return iam_admin_v1.IAMClient(credentials=self._credentials)

    # -- extended service clients (lazy import; gated by the [gcp] extra) --

    def _bigquery_client(self) -> Any:
        from google.cloud import bigquery
        return bigquery.Client(project=self.project_id, credentials=self._credentials)

    def _functions_client(self) -> Any:
        from google.cloud import functions_v2
        return functions_v2.FunctionServiceClient(credentials=self._credentials)

    def _run_client(self) -> Any:
        from google.cloud import run_v2
        return run_v2.ServicesClient(credentials=self._credentials)

    def _sql_admin_client(self) -> Any:
        from googleapiclient import discovery
        return discovery.build(
            "sqladmin", "v1beta4",
            credentials=self._credentials, cache_discovery=False,
        )

    def _spanner_client(self) -> Any:
        from google.cloud import spanner
        return spanner.Client(project=self.project_id, credentials=self._credentials)

    def _redis_client(self) -> Any:
        from google.cloud import redis_v1
        return redis_v1.CloudRedisClient(credentials=self._credentials)

    def _dns_client(self) -> Any:
        from google.cloud import dns
        return dns.Client(project=self.project_id, credentials=self._credentials)

    def _secrets_client(self) -> Any:
        from google.cloud import secretmanager
        return secretmanager.SecretManagerServiceClient(credentials=self._credentials)

    def _artifactregistry_client(self) -> Any:
        from google.cloud import artifactregistry_v1
        return artifactregistry_v1.ArtifactRegistryClient(credentials=self._credentials)

    def _container_client(self) -> Any:
        from google.cloud import container_v1
        return container_v1.ClusterManagerClient(credentials=self._credentials)

    def _kms_client(self) -> Any:
        from google.cloud import kms
        return kms.KeyManagementServiceClient(credentials=self._credentials)

    def _logging_config_client(self) -> Any:
        from google.cloud import logging_v2
        return logging_v2.ConfigServiceV2Client(credentials=self._credentials)

    def _pubsub_client(self) -> Any:
        from google.cloud import pubsub_v1
        return pubsub_v1.PublisherClient(credentials=self._credentials)

    def _resource_manager_client(self) -> Any:
        from google.cloud import resourcemanager_v3
        return resourcemanager_v3.ProjectsClient(credentials=self._credentials)

    # ------------------------------------------------------------------
    # Snapshot factory
    # ------------------------------------------------------------------

    def _snapshot(
        self,
        *,
        resource_type: str,
        resource_name: str,
        region: str,
        config: dict[str, Any],
        tags: dict[str, str] | None = None,
        resource_group: str = "gcp-global",
        cost_monthly: float = 0.0,
    ) -> ResourceSnapshot:
        return ResourceSnapshot(
            tenant_id="",
            provider=CloudProvider.GCP,
            subscription_id=self.project_id,
            resource_group=resource_group,
            resource_type=resource_type,
            resource_name=resource_name,
            region=region or "global",
            config=config,
            tags=tags or {},
            data_tier=DataTier.TIER1_NATIVE,
            cost_monthly=cost_monthly,
            captured_at=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------------------
    # Resource collectors
    # ------------------------------------------------------------------

    def _scan_compute_instances(self) -> list[ResourceSnapshot]:
        """Enumerate Compute Engine instances across every zone."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._compute_instances_client()
            from google.cloud import compute_v1
            request = compute_v1.AggregatedListInstancesRequest(
                project=self.project_id,
            )
            pages = client.aggregated_list(request=request)
        except Exception as exc:  # noqa: BLE001 - best-effort scanner
            logger.warning("GCP compute aggregated_list failed: %s", exc)
            return snaps

        for zone_uri, scoped in pages:
            instances = list(getattr(scoped, "instances", []) or [])
            zone = zone_uri.split("/")[-1] if zone_uri else "global"
            region = zone.rsplit("-", 1)[0] if "-" in zone else zone
            for inst in instances:
                external_ips: list[str] = []
                for nic in list(getattr(inst, "network_interfaces", []) or []):
                    for cfg in list(getattr(nic, "access_configs", []) or []):
                        nat_ip = getattr(cfg, "nat_i_p", "") or getattr(cfg, "nat_ip", "")
                        if nat_ip:
                            external_ips.append(str(nat_ip))
                labels = dict(getattr(inst, "labels", {}) or {})
                oslogin = ""
                meta = getattr(inst, "metadata", None)
                for item in list(getattr(meta, "items", []) or []):
                    if str(getattr(item, "key", "") or "") == "enable-oslogin":
                        oslogin = str(getattr(item, "value", "") or "")
                sa_emails = [
                    str(getattr(sa, "email", "") or "")
                    for sa in (getattr(inst, "service_accounts", []) or [])
                ]
                sic = getattr(inst, "shielded_instance_config", None)
                shielded = {
                    "enable_secure_boot": bool(
                        getattr(sic, "enable_secure_boot", False) if sic else False
                    ),
                    "enable_vtpm": bool(
                        getattr(sic, "enable_vtpm", False) if sic else False
                    ),
                    "enable_integrity_monitoring": bool(
                        getattr(sic, "enable_integrity_monitoring", False)
                        if sic
                        else False
                    ),
                }
                snaps.append(
                    self._snapshot(
                        resource_type="google.compute.Instance",
                        resource_name=str(getattr(inst, "name", "") or ""),
                        region=region,
                        config={
                            "status": str(getattr(inst, "status", "") or ""),
                            "machine_type": str(
                                getattr(inst, "machine_type", "") or ""
                            ).split("/")[-1],
                            "external_ips": external_ips,
                            "zone": zone,
                            "enable_oslogin": oslogin,
                            "service_account_emails": sa_emails,
                            "shielded_instance_config": shielded,
                        },
                        tags=labels,
                    )
                )
        return snaps

    def _scan_compute_disks(self) -> list[ResourceSnapshot]:
        """Enumerate persistent disks across every zone."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._compute_disks_client()
            from google.cloud import compute_v1
            request = compute_v1.AggregatedListDisksRequest(
                project=self.project_id,
            )
            pages = client.aggregated_list(request=request)
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP disks aggregated_list failed: %s", exc)
            return snaps

        for zone_uri, scoped in pages:
            disks = list(getattr(scoped, "disks", []) or [])
            zone = zone_uri.split("/")[-1] if zone_uri else "global"
            region = zone.rsplit("-", 1)[0] if "-" in zone else zone
            for disk in disks:
                users = list(getattr(disk, "users", []) or [])
                dek = getattr(disk, "disk_encryption_key", None)
                cmek = bool(getattr(dek, "kms_key_name", "") if dek else "")
                disk_size = int(getattr(disk, "size_gb", 0) or 0)
                disk_type = str(getattr(disk, "type_", "") or "").split("/")[-1]
                snaps.append(
                    self._snapshot(
                        resource_type="google.compute.Disk",
                        resource_name=str(getattr(disk, "name", "") or ""),
                        region=region,
                        config={
                            "size_gb": disk_size,
                            "status": str(getattr(disk, "status", "") or ""),
                            "users": [str(u) for u in users],
                            "cmek_encrypted": cmek,
                            "type": disk_type,
                        },
                        cost_monthly=gcp_persistent_disk_monthly_usd(
                            disk_type, disk_size
                        ),
                    )
                )
        return snaps

    def _scan_firewalls(self) -> list[ResourceSnapshot]:
        """Enumerate VPC firewall rules."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._compute_firewalls_client()
            from google.cloud import compute_v1
            request = compute_v1.ListFirewallsRequest(project=self.project_id)
            rules = list(client.list(request=request))
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP firewalls list failed: %s", exc)
            return snaps

        for rule in rules:
            allowed = []
            for a in list(getattr(rule, "allowed", []) or []):
                allowed.append(
                    {
                        "protocol": str(
                            getattr(a, "I_p_protocol", "")
                            or getattr(a, "ip_protocol", "")
                        ),
                        "ports": [str(p) for p in (getattr(a, "ports", []) or [])],
                    }
                )
            source_ranges = [str(r) for r in (getattr(rule, "source_ranges", []) or [])]
            snaps.append(
                self._snapshot(
                    resource_type="google.compute.Firewall",
                    resource_name=str(getattr(rule, "name", "") or ""),
                    region="global",
                    config={
                        "direction": str(getattr(rule, "direction", "") or ""),
                        "disabled": bool(getattr(rule, "disabled", False)),
                        "source_ranges": source_ranges,
                        "allowed": allowed,
                        "network": str(getattr(rule, "network", "") or "").split("/")[-1],
                    },
                )
            )
        return snaps

    def _scan_storage_buckets(self) -> list[ResourceSnapshot]:
        """Enumerate GCS buckets with IAM + uniform-access flags."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._storage_client()
            buckets = list(client.list_buckets())
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP list_buckets failed: %s", exc)
            return snaps

        for bucket in buckets:
            uniform = False
            try:
                iam_cfg = getattr(bucket, "iam_configuration", None) or {}
                if isinstance(iam_cfg, dict):
                    uniform = bool(
                        (iam_cfg.get("uniformBucketLevelAccess") or {}).get("enabled")
                    )
                else:
                    ubla = getattr(iam_cfg, "uniform_bucket_level_access", None)
                    uniform = bool(getattr(ubla, "enabled", False))
            except Exception:  # noqa: BLE001
                uniform = False

            public = False
            try:
                policy = bucket.get_iam_policy()
                for binding in policy.bindings:
                    members = binding.get("members") or set()
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        public = True
                        break
            except Exception:  # noqa: BLE001
                public = False

            snaps.append(
                self._snapshot(
                    resource_type="google.storage.Bucket",
                    resource_name=str(getattr(bucket, "name", "") or ""),
                    region=str(getattr(bucket, "location", "") or "").lower() or "global",
                    config={
                        "uniform_bucket_level_access": uniform,
                        "public_iam_member": public,
                        "storage_class": str(getattr(bucket, "storage_class", "") or ""),
                    },
                )
            )
        return snaps

    def _scan_service_accounts(self) -> list[ResourceSnapshot]:
        """Enumerate IAM service accounts (and flag user-managed keys)."""
        snaps: list[ResourceSnapshot] = []
        try:
            from google.cloud import iam_admin_v1
            client = self._iam_admin_client()
            sa_request = iam_admin_v1.ListServiceAccountsRequest(
                name=f"projects/{self.project_id}",
            )
            accounts = list(client.list_service_accounts(request=sa_request).accounts)
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP list_service_accounts failed: %s", exc)
            return snaps

        for sa in accounts:
            sa_email = str(getattr(sa, "email", "") or "")
            user_managed_keys = 0
            try:
                from google.cloud import iam_admin_v1
                key_request = iam_admin_v1.ListServiceAccountKeysRequest(
                    name=f"projects/{self.project_id}/serviceAccounts/{sa_email}",
                )
                keys = client.list_service_account_keys(request=key_request).keys
                for k in keys:
                    key_type = str(getattr(k, "key_type", "") or "")
                    if "USER_MANAGED" in key_type:
                        user_managed_keys += 1
            except Exception:  # noqa: BLE001
                user_managed_keys = 0

            snaps.append(
                self._snapshot(
                    resource_type="google.iam.ServiceAccount",
                    resource_name=sa_email,
                    region="global",
                    config={
                        "display_name": str(getattr(sa, "display_name", "") or ""),
                        "disabled": bool(getattr(sa, "disabled", False)),
                        "user_managed_keys": user_managed_keys,
                    },
                )
            )
        return snaps

    # ------------------------------------------------------------------
    # Extended resource collectors (phase 2)
    # ------------------------------------------------------------------

    @staticmethod
    def _enum_str(value: Any) -> str:
        """Normalise a protobuf enum / wrapper to its string name."""
        if value is None:
            return ""
        return str(getattr(value, "name", value) or "")

    @staticmethod
    def _loc_from_name(name: str) -> str:
        """Extract the location segment from a fully qualified resource name."""
        if "/locations/" in name:
            return name.split("/locations/")[1].split("/")[0]
        return "global"

    @staticmethod
    def _policy_bindings(policy: Any) -> list[dict[str, Any]]:
        """Normalise an IAM policy into a list of {role, members} dicts."""
        out: list[dict[str, Any]] = []
        for b in getattr(policy, "bindings", []) or []:
            out.append(
                {
                    "role": str(getattr(b, "role", "") or ""),
                    "members": [str(m) for m in (getattr(b, "members", []) or [])],
                }
            )
        return out

    @classmethod
    def _invoker_members(cls, policy: Any) -> list[str]:
        """Return members granted any *.invoker role on the resource."""
        members: list[str] = []
        for binding in cls._policy_bindings(policy):
            if "invoker" in binding["role"].lower():
                members.extend(binding["members"])
        return members

    def _scan_bigquery_datasets(self) -> list[ResourceSnapshot]:
        """Enumerate BigQuery datasets (+ tables) with access + CMEK config."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._bigquery_client()
            datasets = list(client.list_datasets())
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP list_datasets failed: %s", exc)
            return snaps

        for ds_ref in datasets:
            try:
                ds = client.get_dataset(ds_ref)
            except Exception:  # noqa: BLE001
                continue
            access: list[dict[str, Any]] = []
            for e in getattr(ds, "access_entries", []) or []:
                et = str(getattr(e, "entity_type", "") or "")
                eid = str(getattr(e, "entity_id", "") or "")
                access.append(
                    {
                        "role": str(getattr(e, "role", "") or ""),
                        "specialGroup": eid if et == "specialGroup" else "",
                        "iamMember": eid if et == "iamMember" else "",
                        "userByEmail": eid if et == "userByEmail" else "",
                    }
                )
            enc = getattr(ds, "default_encryption_configuration", None)
            kms = str(getattr(enc, "kms_key_name", "") or "") if enc else ""
            ds_id = str(
                getattr(ds, "dataset_id", "")
                or getattr(ds_ref, "dataset_id", "")
                or ""
            )
            region = str(getattr(ds, "location", "") or "").lower() or "global"
            snaps.append(
                self._snapshot(
                    resource_type="google.bigquery.Dataset",
                    resource_name=ds_id,
                    region=region,
                    config={"access": access, "default_kms_key_name": kms},
                )
            )
            try:
                tables = list(client.list_tables(ds_ref))
            except Exception:  # noqa: BLE001
                tables = []
            for t_ref in tables:
                try:
                    t = client.get_table(t_ref)
                except Exception:  # noqa: BLE001
                    continue
                tp = getattr(t, "time_partitioning", None)
                tp_dict: dict[str, Any] = {}
                if tp:
                    tp_dict = {
                        "type": self._enum_str(getattr(tp, "type_", None)),
                        "expiration_ms": getattr(tp, "expiration_ms", None),
                    }
                snaps.append(
                    self._snapshot(
                        resource_type="google.bigquery.Table",
                        resource_name=str(getattr(t, "table_id", "") or ""),
                        region=str(getattr(t, "location", "") or "").lower() or region,
                        config={"time_partitioning": tp_dict},
                    )
                )
        return snaps

    def _scan_cloud_functions(self) -> list[ResourceSnapshot]:
        """Enumerate Cloud Functions (gen2) ingress + invoker bindings."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._functions_client()
            parent = f"projects/{self.project_id}/locations/-"
            functions = list(client.list_functions(parent=parent))
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP list_functions failed: %s", exc)
            return snaps

        for fn in functions:
            name = str(getattr(fn, "name", "") or "")
            svc_cfg = getattr(fn, "service_config", None)
            ingress = self._enum_str(
                getattr(svc_cfg, "ingress_settings", None) if svc_cfg else None
            )
            invoker: list[str] = []
            try:
                policy = client.get_iam_policy(request={"resource": name})
                invoker = self._invoker_members(policy)
            except Exception:  # noqa: BLE001
                invoker = []
            snaps.append(
                self._snapshot(
                    resource_type="google.cloudfunctions.Function",
                    resource_name=name.split("/")[-1] or name,
                    region=self._loc_from_name(name),
                    config={"ingress_settings": ingress, "invoker_members": invoker},
                )
            )
        return snaps

    def _scan_cloud_run(self) -> list[ResourceSnapshot]:
        """Enumerate Cloud Run services with ingress + invoker bindings."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._run_client()
            parent = f"projects/{self.project_id}/locations/-"
            services = list(client.list_services(parent=parent))
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP list_services failed: %s", exc)
            return snaps

        for svc in services:
            name = str(getattr(svc, "name", "") or "")
            ingress_raw = self._enum_str(getattr(svc, "ingress", None))
            ingress = (
                "all"
                if ingress_raw.upper() in ("ALL", "INGRESS_TRAFFIC_ALL")
                else ingress_raw
            )
            invoker: list[str] = []
            try:
                policy = client.get_iam_policy(request={"resource": name})
                invoker = self._invoker_members(policy)
            except Exception:  # noqa: BLE001
                invoker = []
            snaps.append(
                self._snapshot(
                    resource_type="google.run.Service",
                    resource_name=name.split("/")[-1] or name,
                    region=self._loc_from_name(name),
                    config={"ingress": ingress, "invoker_members": invoker},
                )
            )
        return snaps

    def _scan_cloud_sql(self) -> list[ResourceSnapshot]:
        """Enumerate Cloud SQL instances via the Admin API."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._sql_admin_client()
            resp = client.instances().list(project=self.project_id).execute()
            items = list(resp.get("items", []) or [])
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP sql instances list failed: %s", exc)
            return snaps

        for inst in items:
            settings = inst.get("settings", {}) or {}
            ip_cfg = settings.get("ipConfiguration", {}) or {}
            backup_cfg = settings.get("backupConfiguration", {}) or {}
            snaps.append(
                self._snapshot(
                    resource_type="google.sql.Instance",
                    resource_name=str(inst.get("name", "") or ""),
                    region=str(inst.get("region", "") or "").lower() or "global",
                    config={
                        "ipv4_enabled": bool(ip_cfg.get("ipv4Enabled")),
                        "require_ssl": bool(ip_cfg.get("requireSsl")),
                        "backup_enabled": bool(backup_cfg.get("enabled")),
                    },
                )
            )
        return snaps

    def _scan_spanner(self) -> list[ResourceSnapshot]:
        """Enumerate Spanner databases and their CMEK config."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._spanner_client()
            instances = list(client.list_instances())
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP spanner list_instances failed: %s", exc)
            return snaps

        for inst in instances:
            try:
                databases = list(inst.list_databases())
            except Exception:  # noqa: BLE001
                databases = []
            for db in databases:
                name = str(getattr(db, "name", "") or "")
                enc = getattr(db, "encryption_config", None)
                kms = str(getattr(enc, "kms_key_name", "") or "") if enc else ""
                snaps.append(
                    self._snapshot(
                        resource_type="google.spanner.Database",
                        resource_name=name.split("/")[-1] or name,
                        region="global",
                        config={"kms_key_name": kms},
                    )
                )
        return snaps

    def _scan_redis(self) -> list[ResourceSnapshot]:
        """Enumerate Memorystore (Redis) instances."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._redis_client()
            parent = f"projects/{self.project_id}/locations/-"
            instances = list(client.list_instances(parent=parent))
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP redis list_instances failed: %s", exc)
            return snaps

        for inst in instances:
            name = str(getattr(inst, "name", "") or "")
            snaps.append(
                self._snapshot(
                    resource_type="google.redis.Instance",
                    resource_name=name.split("/")[-1] or name,
                    region=self._loc_from_name(name),
                    config={
                        "auth_enabled": bool(getattr(inst, "auth_enabled", False)),
                        "transit_encryption_mode": self._enum_str(
                            getattr(inst, "transit_encryption_mode", None)
                        ),
                    },
                )
            )
        return snaps

    def _scan_dns_zones(self) -> list[ResourceSnapshot]:
        """Enumerate Cloud DNS managed zones."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._dns_client()
            zones = list(client.list_zones())
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP dns list_zones failed: %s", exc)
            return snaps

        for zone in zones:
            snaps.append(
                self._snapshot(
                    resource_type="google.dns.ManagedZone",
                    resource_name=str(getattr(zone, "name", "") or ""),
                    region="global",
                    config={
                        "visibility": str(
                            getattr(zone, "visibility", "public") or "public"
                        ),
                        "dnssec_state": self._enum_str(
                            getattr(zone, "dnssec_state", None)
                        ),
                    },
                )
            )
        return snaps

    def _scan_secrets(self) -> list[ResourceSnapshot]:
        """Enumerate Secret Manager secrets + CMEK config."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._secrets_client()
            secrets = list(
                client.list_secrets(request={"parent": f"projects/{self.project_id}"})
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP list_secrets failed: %s", exc)
            return snaps

        for secret in secrets:
            name = str(getattr(secret, "name", "") or "")
            cmek = getattr(secret, "customer_managed_encryption", None)
            kms = str(getattr(cmek, "kms_key_name", "") or "") if cmek else ""
            snaps.append(
                self._snapshot(
                    resource_type="google.secretmanager.Secret",
                    resource_name=name.split("/")[-1] or name,
                    region="global",
                    config={"customer_managed_kms_key": kms},
                )
            )
        return snaps

    def _scan_artifact_registry(self) -> list[ResourceSnapshot]:
        """Enumerate Artifact Registry repositories + IAM bindings."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._artifactregistry_client()
            parent = f"projects/{self.project_id}/locations/-"
            repos = list(client.list_repositories(parent=parent))
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP list_repositories failed: %s", exc)
            return snaps

        for repo in repos:
            name = str(getattr(repo, "name", "") or "")
            bindings: list[dict[str, Any]] = []
            try:
                policy = client.get_iam_policy(request={"resource": name})
                bindings = self._policy_bindings(policy)
            except Exception:  # noqa: BLE001
                bindings = []
            snaps.append(
                self._snapshot(
                    resource_type="google.artifactregistry.Repository",
                    resource_name=name.split("/")[-1] or name,
                    region=self._loc_from_name(name),
                    config={
                        "kms_key_name": str(getattr(repo, "kms_key_name", "") or ""),
                        "iam_bindings": bindings,
                    },
                )
            )
        return snaps

    def _scan_gke_clusters(self) -> list[ResourceSnapshot]:
        """Enumerate GKE clusters (+ node pools) hardening posture."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._container_client()
            parent = f"projects/{self.project_id}/locations/-"
            resp = client.list_clusters(parent=parent)
            clusters = list(getattr(resp, "clusters", []) or [])
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP list_clusters failed: %s", exc)
            return snaps

        for cluster in clusters:
            name = str(getattr(cluster, "name", "") or "")
            region = str(getattr(cluster, "location", "") or "") or "global"
            pcc = getattr(cluster, "private_cluster_config", None)
            npol = getattr(cluster, "network_policy", None)
            wic = getattr(cluster, "workload_identity_config", None)
            ba = getattr(cluster, "binary_authorization", None)
            snaps.append(
                self._snapshot(
                    resource_type="google.container.Cluster",
                    resource_name=name,
                    region=region,
                    config={
                        "enable_private_nodes": bool(
                            getattr(pcc, "enable_private_nodes", False) if pcc else False
                        ),
                        "logging_service": str(
                            getattr(cluster, "logging_service", "") or ""
                        ),
                        "network_policy_enabled": bool(
                            getattr(npol, "enabled", False) if npol else False
                        ),
                        "workload_identity_pool": str(
                            getattr(wic, "workload_pool", "") if wic else ""
                        ),
                        "binary_authorization_mode": self._enum_str(
                            getattr(ba, "evaluation_mode", None) if ba else None
                        ),
                    },
                )
            )
            for pool in getattr(cluster, "node_pools", []) or []:
                mgmt = getattr(pool, "management", None)
                snaps.append(
                    self._snapshot(
                        resource_type="google.container.NodePool",
                        resource_name=str(getattr(pool, "name", "") or ""),
                        region=region,
                        config={
                            "auto_upgrade": bool(
                                getattr(mgmt, "auto_upgrade", False) if mgmt else False
                            ),
                        },
                    )
                )
        return snaps

    def _scan_kms_keys(self) -> list[ResourceSnapshot]:
        """Enumerate KMS crypto keys (rotation + IAM exposure)."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._kms_client()
            parent = f"projects/{self.project_id}/locations/global"
            rings = list(client.list_key_rings(parent=parent))
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP list_key_rings failed: %s", exc)
            return snaps

        for ring in rings:
            ring_name = str(getattr(ring, "name", "") or "")
            try:
                keys = list(client.list_crypto_keys(parent=ring_name))
            except Exception:  # noqa: BLE001
                keys = []
            for key in keys:
                name = str(getattr(key, "name", "") or "")
                rp = getattr(key, "rotation_period", None)
                rotation_days = None
                if rp is not None:
                    secs = int(getattr(rp, "seconds", 0) or 0)
                    rotation_days = secs // 86400 if secs else None
                bindings: list[dict[str, Any]] = []
                try:
                    policy = client.get_iam_policy(request={"resource": name})
                    bindings = self._policy_bindings(policy)
                except Exception:  # noqa: BLE001
                    bindings = []
                snaps.append(
                    self._snapshot(
                        resource_type="google.kms.CryptoKey",
                        resource_name=name.split("/")[-1] or name,
                        region="global",
                        config={
                            "rotation_period_days": rotation_days,
                            "iam_bindings": bindings,
                        },
                    )
                )
        return snaps

    def _scan_logging(self) -> list[ResourceSnapshot]:
        """Emit a project log-sink summary + per-bucket retention snapshots."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._logging_config_client()
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP logging client init failed: %s", exc)
            return snaps

        sinks: list[dict[str, Any]] = []
        try:
            for sink in client.list_sinks(parent=f"projects/{self.project_id}"):
                sinks.append(
                    {
                        "name": str(getattr(sink, "name", "") or ""),
                        "filter": str(getattr(sink, "filter", "") or ""),
                    }
                )
        except Exception:  # noqa: BLE001
            sinks = []
        snaps.append(
            self._snapshot(
                resource_type="google.logging.Project",
                resource_name=self.project_id,
                region="global",
                config={"sinks": sinks},
            )
        )

        try:
            parent = f"projects/{self.project_id}/locations/-"
            for bucket in client.list_buckets(parent=parent):
                name = str(getattr(bucket, "name", "") or "")
                snaps.append(
                    self._snapshot(
                        resource_type="google.logging.LogBucket",
                        resource_name=name.split("/")[-1] or name,
                        region=self._loc_from_name(name),
                        config={
                            "retention_days": int(
                                getattr(bucket, "retention_days", 0) or 0
                            ),
                        },
                    )
                )
        except Exception:  # noqa: BLE001
            pass
        return snaps

    def _scan_pubsub_topics(self) -> list[ResourceSnapshot]:
        """Enumerate Pub/Sub topics (CMEK + IAM exposure)."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._pubsub_client()
            topics = list(
                client.list_topics(request={"project": f"projects/{self.project_id}"})
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP list_topics failed: %s", exc)
            return snaps

        for topic in topics:
            name = str(getattr(topic, "name", "") or "")
            bindings: list[dict[str, Any]] = []
            try:
                policy = client.get_iam_policy(request={"resource": name})
                bindings = self._policy_bindings(policy)
            except Exception:  # noqa: BLE001
                bindings = []
            snaps.append(
                self._snapshot(
                    resource_type="google.pubsub.Topic",
                    resource_name=name.split("/")[-1] or name,
                    region="global",
                    config={
                        "kms_key_name": str(getattr(topic, "kms_key_name", "") or ""),
                        "iam_bindings": bindings,
                    },
                )
            )
        return snaps

    def _scan_project_iam(self) -> list[ResourceSnapshot]:
        """Emit a single snapshot carrying the project-level IAM bindings."""
        snaps: list[ResourceSnapshot] = []
        try:
            client = self._resource_manager_client()
            policy = client.get_iam_policy(
                request={"resource": f"projects/{self.project_id}"}
            )
            bindings = self._policy_bindings(policy)
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP project get_iam_policy failed: %s", exc)
            return snaps

        snaps.append(
            self._snapshot(
                resource_type="google.iam.ProjectPolicy",
                resource_name=self.project_id,
                region="global",
                config={"bindings": bindings},
            )
        )
        return snaps

    # ------------------------------------------------------------------
    # AdapterBase contract
    # ------------------------------------------------------------------

    async def scan(self) -> list[ResourceSnapshot]:
        """Scan the configured project and return all snapshots."""
        _require_google()

        def _collect() -> list[ResourceSnapshot]:
            return [
                *self._scan_compute_instances(),
                *self._scan_compute_disks(),
                *self._scan_firewalls(),
                *self._scan_storage_buckets(),
                *self._scan_service_accounts(),
                *self._scan_bigquery_datasets(),
                *self._scan_cloud_functions(),
                *self._scan_cloud_run(),
                *self._scan_cloud_sql(),
                *self._scan_spanner(),
                *self._scan_redis(),
                *self._scan_dns_zones(),
                *self._scan_secrets(),
                *self._scan_artifact_registry(),
                *self._scan_gke_clusters(),
                *self._scan_kms_keys(),
                *self._scan_logging(),
                *self._scan_pubsub_topics(),
                *self._scan_project_iam(),
            ]

        snapshots, self._policy_findings = await asyncio.gather(
            asyncio.to_thread(_collect),
            self._policy_adapter.fetch_findings(),
        )
        logger.info(
            "GCP scan returned %d snapshots, %d policy finding(s)",
            len(snapshots),
            len(self._policy_findings),
        )
        return snapshots

    async def fetch_policy_findings(self) -> list[FindingResult]:
        """Fetch GCP policy compliance findings on demand."""
        self._policy_findings = await self._policy_adapter.fetch_findings()
        return self._policy_findings

    @property
    def policy_findings(self) -> list[FindingResult]:
        """Policy compliance findings from the most recent scan."""
        return self._policy_findings

    async def validate_connection(self) -> bool:
        """Return True when a lightweight project read succeeds."""
        _require_google()

        def _check() -> bool:
            try:
                client = self._storage_client()
                # list_buckets is paginated; pulling the first item is enough
                # to validate auth without enumerating the whole project.
                iterator = iter(client.list_buckets(max_results=1))
                next(iterator, None)
                return True
            except Exception as exc:  # noqa: BLE001
                logger.warning("GCP validate_connection failed: %s", exc)
                return False

        return await asyncio.to_thread(_check)

    async def get_api_contract(self) -> dict[str, Any]:
        """Return the (frozen) contract this adapter relies on."""
        return {
            "provider": "GCP",
            "services": [
                "compute",
                "storage",
                "iam",
            ],
            "operations": [
                "compute.instances.aggregatedList",
                "compute.disks.aggregatedList",
                "compute.firewalls.list",
                "storage.buckets.list",
                "storage.buckets.getIamPolicy",
                "iam.serviceAccounts.list",
                "iam.serviceAccountKeys.list",
            ],
        }

    # ------------------------------------------------------------------
    # Legacy AdapterBase methods (Azure-shaped; GCP impls are no-ops)
    # ------------------------------------------------------------------

    async def list_resources(self, subscription_id: str) -> list[ResourceSnapshot]:
        """List resources for the GCP project (subscription_id == project_id)."""
        if subscription_id and subscription_id != self.project_id:
            logger.debug(
                "GCPAdapter.list_resources called with project=%s "
                "but adapter is bound to %s",
                subscription_id,
                self.project_id,
            )
        return await self.scan()

    async def get_resource(self, resource_id: str) -> ResourceSnapshot | None:
        """Single-resource fetch is not implemented for the V1 GCP adapter."""
        logger.debug("GCPAdapter.get_resource not implemented (id=%s)", resource_id)
        return None

    async def get_cost(self, resource_id: str) -> float:
        """GCP Billing integration is not wired in the V1 adapter."""
        return 0.0

    async def enrich_with_defender(
        self, snapshots: list[ResourceSnapshot]
    ) -> list[ResourceSnapshot]:
        """Defender is an Azure concept; return snapshots unchanged."""
        return snapshots

    async def get_raw_properties(self, resource_id: str) -> dict[str, Any]:
        """Raw-property fetch is not implemented for the V1 GCP adapter."""
        return {}

