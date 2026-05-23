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
from cloudguardiq.adapters.pricing import gcp_persistent_disk_monthly_usd
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import ResourceSnapshot

logger = logging.getLogger(__name__)


def _require_google() -> None:
    """Import the google client libraries lazily; raise a friendly error
    when the optional ``[gcp]`` extra is not installed."""
    try:
        import google.cloud.compute_v1  # type: ignore[import-not-found]  # noqa: F401
        import google.cloud.storage  # type: ignore[import-not-found]  # noqa: F401
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

    # ------------------------------------------------------------------
    # Client helpers
    # ------------------------------------------------------------------

    def _compute_instances_client(self) -> Any:
        from google.cloud import compute_v1  # type: ignore[import-not-found]
        return compute_v1.InstancesClient(credentials=self._credentials)

    def _compute_disks_client(self) -> Any:
        from google.cloud import compute_v1  # type: ignore[import-not-found]
        return compute_v1.DisksClient(credentials=self._credentials)

    def _compute_firewalls_client(self) -> Any:
        from google.cloud import compute_v1  # type: ignore[import-not-found]
        return compute_v1.FirewallsClient(credentials=self._credentials)

    def _storage_client(self) -> Any:
        from google.cloud import storage  # type: ignore[import-not-found]
        return storage.Client(
            project=self.project_id,
            credentials=self._credentials,
        )

    def _iam_admin_client(self) -> Any:
        from google.cloud import iam_admin_v1  # type: ignore[import-not-found]
        return iam_admin_v1.IAMClient(credentials=self._credentials)

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
            from google.cloud import compute_v1  # type: ignore[import-not-found]
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
            from google.cloud import compute_v1  # type: ignore[import-not-found]
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
            from google.cloud import compute_v1  # type: ignore[import-not-found]
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
            from google.cloud import iam_admin_v1  # type: ignore[import-not-found]
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
                from google.cloud import iam_admin_v1  # type: ignore[import-not-found]
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
            ]

        return await asyncio.to_thread(_collect)

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
