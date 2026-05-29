"""CloudGuardIQ — AWS read-only adapter.

Enumerates a curated set of AWS resources via boto3 and emits
``ResourceSnapshot`` objects that the cloud-agnostic ``PolicyEngine``
and ``AWS_RULE_REGISTRY`` can evaluate.

boto3 is imported lazily so that the rest of CloudGuardIQ (which is
Azure-first today) does not require ``boto3`` to be installed.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from cloudguardiq.adapters.base import AdapterBase
from cloudguardiq.adapters.pricing import (
    aws_ebs_monthly_usd,
    aws_eip_unattached_monthly_usd,
)
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import ResourceSnapshot

logger = logging.getLogger(__name__)


def _require_boto3() -> Any:
    """Import boto3 lazily; raise a friendly error when not installed."""
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - guarded path
        raise RuntimeError(
            "AWSAdapter requires the optional [aws] extra. "
            "Install with: pip install 'cloudguardiq[aws]'"
        ) from exc
    return boto3


class AWSAdapter(AdapterBase):
    """Read-only AWS adapter (Tier-1 native scanning).

    Args:
        account_id: AWS account id (string). Populated into
            ``ResourceSnapshot.subscription_id`` so the cloud-agnostic
            data model stays consistent.
        region: Default AWS region for regional services (EC2, EBS,
            SGs, EIPs). Defaults to ``us-east-1``.
        session: Optional pre-built ``boto3.Session``. When omitted,
            the default boto3 credential chain is used.
    """

    PROVIDER = CloudProvider.AWS

    def __init__(
        self,
        account_id: str,
        region: str = "us-east-1",
        session: Any | None = None,
    ) -> None:
        self.account_id = account_id
        self.region = region
        self._session = session

    # ------------------------------------------------------------------
    # Session / client helpers
    # ------------------------------------------------------------------

    def _get_session(self) -> Any:
        if self._session is not None:
            return self._session
        boto3 = _require_boto3()
        self._session = boto3.Session(region_name=self.region)
        return self._session

    def _client(self, service: str) -> Any:
        return self._get_session().client(service)

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
        resource_group: str = "aws-global",
        cost_monthly: float = 0.0,
    ) -> ResourceSnapshot:
        return ResourceSnapshot(
            tenant_id="",
            provider=CloudProvider.AWS,
            subscription_id=self.account_id,
            resource_group=resource_group,
            resource_type=resource_type,
            resource_name=resource_name,
            region=region or self.region,
            config=config,
            tags=tags or {},
            data_tier=DataTier.TIER1_NATIVE,
            cost_monthly=cost_monthly,
            captured_at=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------------------
    # Resource collectors
    # ------------------------------------------------------------------

    def _scan_s3_buckets(self) -> list[ResourceSnapshot]:
        """Enumerate S3 buckets with ACL, public-access-block, and encryption."""
        s3 = self._client("s3")
        snaps: list[ResourceSnapshot] = []
        try:
            buckets = s3.list_buckets().get("Buckets") or []
        except Exception as exc:  # noqa: BLE001 - best-effort scanner
            logger.warning("AWS S3 list_buckets failed: %s", exc)
            return snaps

        for b in buckets:
            name = b.get("Name") or ""
            try:
                acl = s3.get_bucket_acl(Bucket=name)
            except Exception as exc:  # noqa: BLE001
                logger.debug("get_bucket_acl(%s) failed: %s", name, exc)
                acl = {}
            try:
                pab = (
                    s3.get_public_access_block(Bucket=name)
                    .get("PublicAccessBlockConfiguration")
                    or {}
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("get_public_access_block(%s) failed: %s", name, exc)
                pab = {}
            try:
                enc = (
                    s3.get_bucket_encryption(Bucket=name)
                    .get("ServerSideEncryptionConfiguration")
                    or {}
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("get_bucket_encryption(%s) failed: %s", name, exc)
                enc = {}
            try:
                loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            except Exception:  # noqa: BLE001
                loc = None
            snaps.append(
                self._snapshot(
                    resource_type="AWS::S3::Bucket",
                    resource_name=name,
                    region=loc or "us-east-1",
                    config={
                        "acl": acl,
                        "public_access_block": pab,
                        "encryption": enc,
                    },
                )
            )
        return snaps

    def _scan_ebs_volumes(self) -> list[ResourceSnapshot]:
        ec2 = self._client("ec2")
        snaps: list[ResourceSnapshot] = []
        try:
            paginator = ec2.get_paginator("describe_volumes")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("describe_volumes failed: %s", exc)
            return snaps
        for page in pages:
            for vol in page.get("Volumes") or []:
                vol_id = vol.get("VolumeId") or ""
                tags = {
                    t.get("Key", ""): t.get("Value", "")
                    for t in (vol.get("Tags") or [])
                }
                vol_type = vol.get("VolumeType")
                vol_size = vol.get("Size") or 0
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::EC2::Volume",
                        resource_name=vol_id,
                        region=vol.get("AvailabilityZone", self.region)[:-1] or self.region,
                        config={
                            "encrypted": vol.get("Encrypted", False),
                            "state": vol.get("State"),
                            "size": vol_size,
                            "attachments": vol.get("Attachments") or [],
                            "volume_type": vol_type,
                        },
                        tags=tags,
                        cost_monthly=aws_ebs_monthly_usd(vol_type, vol_size),
                    )
                )
        return snaps

    def _scan_ec2_instances(self) -> list[ResourceSnapshot]:
        ec2 = self._client("ec2")
        snaps: list[ResourceSnapshot] = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("describe_instances failed: %s", exc)
            return snaps
        for page in pages:
            for res in page.get("Reservations") or []:
                for inst in res.get("Instances") or []:
                    iid = inst.get("InstanceId") or ""
                    tags = {
                        t.get("Key", ""): t.get("Value", "")
                        for t in (inst.get("Tags") or [])
                    }
                    snaps.append(
                        self._snapshot(
                            resource_type="AWS::EC2::Instance",
                            resource_name=iid,
                            region=self.region,
                            config={
                                "state": (inst.get("State") or {}).get("Name"),
                                "public_ip_address": inst.get("PublicIpAddress"),
                                "instance_type": inst.get("InstanceType"),
                                "vpc_id": inst.get("VpcId"),
                            },
                            tags=tags,
                        )
                    )
        return snaps

    def _scan_security_groups(self) -> list[ResourceSnapshot]:
        ec2 = self._client("ec2")
        snaps: list[ResourceSnapshot] = []
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("describe_security_groups failed: %s", exc)
            return snaps
        for page in pages:
            for sg in page.get("SecurityGroups") or []:
                gid = sg.get("GroupId") or ""
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::EC2::SecurityGroup",
                        resource_name=gid,
                        region=self.region,
                        config={
                            "group_name": sg.get("GroupName"),
                            "vpc_id": sg.get("VpcId"),
                            "ingress_rules": sg.get("IpPermissions") or [],
                            "egress_rules": sg.get("IpPermissionsEgress") or [],
                        },
                    )
                )
        return snaps

    def _scan_iam(self) -> list[ResourceSnapshot]:
        iam = self._client("iam")
        snaps: list[ResourceSnapshot] = []
        try:
            summary = iam.get_account_summary().get("SummaryMap") or {}
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_account_summary failed: %s", exc)
            summary = {}
        snaps.append(
            self._snapshot(
                resource_type="AWS::IAM::AccountSummary",
                resource_name=self.account_id,
                region="global",
                config={"summary_map": summary},
            )
        )
        # IAM users with credential-report-derived MFA + console flags
        try:
            paginator = iam.get_paginator("list_users")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_users failed: %s", exc)
            return snaps
        for page in pages:
            for u in page.get("Users") or []:
                name = u.get("UserName") or ""
                password_enabled = u.get("PasswordLastUsed") is not None
                try:
                    mfa = iam.list_mfa_devices(UserName=name).get("MFADevices") or []
                except Exception:  # noqa: BLE001
                    mfa = []
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::IAM::User",
                        resource_name=name,
                        region="global",
                        config={
                            "password_enabled": password_enabled,
                            "mfa_active": len(mfa) > 0,
                            "user_id": u.get("UserId"),
                            "arn": u.get("Arn"),
                        },
                    )
                )
        return snaps

    def _scan_eips(self) -> list[ResourceSnapshot]:
        ec2 = self._client("ec2")
        snaps: list[ResourceSnapshot] = []
        try:
            addrs = ec2.describe_addresses().get("Addresses") or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("describe_addresses failed: %s", exc)
            return snaps
        for a in addrs:
            alloc = a.get("AllocationId") or a.get("PublicIp") or ""
            assoc_id = a.get("AssociationId")
            # AWS bills every public IPv4 hourly; the cost is only "waste"
            # when the EIP is not associated with a running resource.
            eip_cost = 0.0 if assoc_id else aws_eip_unattached_monthly_usd()
            snaps.append(
                self._snapshot(
                    resource_type="AWS::EC2::EIP",
                    resource_name=alloc,
                    region=self.region,
                    config={
                        "association_id": assoc_id,
                        "public_ip": a.get("PublicIp"),
                        "domain": a.get("Domain"),
                    },
                    cost_monthly=eip_cost,
                )
            )
        return snaps

    # ------------------------------------------------------------------
    # AdapterBase contract
    # ------------------------------------------------------------------

    async def scan(self) -> list[ResourceSnapshot]:
        """Scan the configured account/region and return all snapshots."""
        def _collect() -> list[ResourceSnapshot]:
            return [
                *self._scan_s3_buckets(),
                *self._scan_ebs_volumes(),
                *self._scan_ec2_instances(),
                *self._scan_security_groups(),
                *self._scan_iam(),
                *self._scan_eips(),
            ]

        return await asyncio.to_thread(_collect)

    async def validate_connection(self) -> bool:
        """Return True when STS GetCallerIdentity succeeds."""
        def _check() -> bool:
            try:
                sts = self._client("sts")
                sts.get_caller_identity()
                return True
            except Exception as exc:  # noqa: BLE001
                logger.warning("AWS validate_connection failed: %s", exc)
                return False

        return await asyncio.to_thread(_check)

    async def get_api_contract(self) -> dict[str, Any]:
        """Return the (frozen) contract this adapter relies on."""
        return {
            "provider": "AWS",
            "services": [
                "s3", "ec2", "iam", "sts",
            ],
            "operations": [
                "s3:ListBuckets",
                "s3:GetBucketAcl",
                "s3:GetPublicAccessBlock",
                "s3:GetBucketEncryption",
                "s3:GetBucketLocation",
                "ec2:DescribeVolumes",
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeAddresses",
                "iam:GetAccountSummary",
                "iam:ListUsers",
                "iam:ListMFADevices",
                "sts:GetCallerIdentity",
            ],
        }

    # ------------------------------------------------------------------
    # Legacy AdapterBase methods (Azure-shaped; AWS impls are no-ops)
    # ------------------------------------------------------------------

    async def list_resources(self, subscription_id: str) -> list[ResourceSnapshot]:
        """List resources for the AWS account (subscription_id == account_id)."""
        if subscription_id and subscription_id != self.account_id:
            logger.debug(
                "AWSAdapter.list_resources called with account_id=%s "
                "but adapter is bound to %s",
                subscription_id,
                self.account_id,
            )
        return await self.scan()

    async def get_resource(self, resource_id: str) -> ResourceSnapshot | None:
        """Single-resource fetch is not implemented for the V1 AWS adapter."""
        logger.debug("AWSAdapter.get_resource not implemented (id=%s)", resource_id)
        return None

    async def get_cost(self, resource_id: str) -> float:
        """AWS Cost Explorer integration is not wired in the V1 adapter."""
        return 0.0

    async def enrich_with_defender(
        self, snapshots: list[ResourceSnapshot]
    ) -> list[ResourceSnapshot]:
        """Defender is an Azure concept; return snapshots unchanged."""
        return snapshots

    async def get_raw_properties(self, resource_id: str) -> dict[str, Any]:
        """Raw-property fetch is not implemented for the V1 AWS adapter."""
        return {}
