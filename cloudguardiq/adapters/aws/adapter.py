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

from cloudguardiq.adapters.aws.aws_policy_compliance_adapter import (
    AWSPolicyComplianceAdapter,
)
from cloudguardiq.adapters.base import AdapterBase
from cloudguardiq.adapters.pricing import (
    aws_ebs_monthly_usd,
    aws_eip_unattached_monthly_usd,
)
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

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
        self._policy_adapter = AWSPolicyComplianceAdapter(
            account_id=account_id,
            region=region,
            session=session,
        )
        self._policy_findings: list[FindingResult] = []

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
                            "ip_permissions": sg.get("IpPermissions") or [],
                            "ip_permissions_egress": sg.get("IpPermissionsEgress") or [],
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
        # Account password policy (AWS-IAM-003)
        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy") or {}
        except Exception as exc:  # noqa: BLE001 - no policy set or denied
            logger.warning("get_account_password_policy failed: %s", exc)
            policy = {}
        snaps.append(
            self._snapshot(
                resource_type="AWS::IAM::PasswordPolicy",
                resource_name=f"{self.account_id}-password-policy",
                region="global",
                config={
                    "minimum_password_length": policy.get("MinimumPasswordLength", 0),
                    "require_symbols": policy.get("RequireSymbols", False),
                    "require_numbers": policy.get("RequireNumbers", False),
                    "require_uppercase": policy.get("RequireUppercaseCharacters", False),
                    "require_lowercase": policy.get("RequireLowercaseCharacters", False),
                    "password_reuse_prevention": policy.get("PasswordReusePrevention", 0),
                    "max_password_age": policy.get("MaxPasswordAge", 0),
                },
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
                access_keys = self._iam_access_keys(iam, name)
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
                            "access_keys": access_keys,
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
    # Resource collectors (Phase 2 — expanded coverage)
    # ------------------------------------------------------------------

    def _iam_access_keys(self, iam: Any, user_name: str) -> list[dict[str, Any]]:
        """Return active/inactive access keys with age in days for a user."""
        from datetime import datetime, timezone

        keys: list[dict[str, Any]] = []
        try:
            meta = iam.list_access_keys(UserName=user_name).get(
                "AccessKeyMetadata"
            ) or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_access_keys failed for %s: %s", user_name, exc)
            return keys
        now = datetime.now(timezone.utc)
        for k in meta:
            created = k.get("CreateDate")
            age_days = 0
            if isinstance(created, datetime):
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age_days = (now - created).days
            keys.append(
                {
                    "access_key_id": k.get("AccessKeyId"),
                    "status": k.get("Status"),
                    "age_days": age_days,
                }
            )
        return keys

    def _scan_vpcs(self) -> list[ResourceSnapshot]:
        """Enumerate VPCs and whether VPC flow logs are enabled (AWS-VPC-001)."""
        snaps: list[ResourceSnapshot] = []
        try:
            ec2 = self._client("ec2")
            vpcs = ec2.describe_vpcs().get("Vpcs") or []
            flow_logs = ec2.describe_flow_logs().get("FlowLogs") or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("describe_vpcs/flow_logs failed: %s", exc)
            return snaps
        enabled_vpc_ids = {
            fl.get("ResourceId")
            for fl in flow_logs
            if str(fl.get("FlowLogStatus", "")).upper() == "ACTIVE"
        }
        for vpc in vpcs:
            vpc_id = vpc.get("VpcId") or ""
            tags = {
                t.get("Key", ""): t.get("Value", "")
                for t in (vpc.get("Tags") or [])
            }
            snaps.append(
                self._snapshot(
                    resource_type="AWS::EC2::VPC",
                    resource_name=vpc_id,
                    region=self.region,
                    config={"flow_logs_enabled": vpc_id in enabled_vpc_ids},
                    tags=tags,
                )
            )
        return snaps

    def _scan_rds(self) -> list[ResourceSnapshot]:
        """Enumerate RDS DB instances (encryption, public access, backups)."""
        snaps: list[ResourceSnapshot] = []
        try:
            rds = self._client("rds")
            paginator = rds.get_paginator("describe_db_instances")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("describe_db_instances failed: %s", exc)
            return snaps
        for page in pages:
            for db in page.get("DBInstances") or []:
                name = db.get("DBInstanceIdentifier") or ""
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::RDS::DBInstance",
                        resource_name=name,
                        region=self.region,
                        config={
                            "storage_encrypted": db.get("StorageEncrypted", False),
                            "publicly_accessible": db.get("PubliclyAccessible", False),
                            "backup_retention_period": db.get(
                                "BackupRetentionPeriod", 0
                            ),
                            "engine": db.get("Engine"),
                        },
                    )
                )
        return snaps

    def _scan_eks(self) -> list[ResourceSnapshot]:
        """Enumerate EKS clusters (logging, public endpoint, secrets encryption)."""
        snaps: list[ResourceSnapshot] = []
        try:
            eks = self._client("eks")
            names = eks.list_clusters().get("clusters") or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_clusters failed: %s", exc)
            return snaps
        for cname in names:
            try:
                cluster = eks.describe_cluster(name=cname).get("cluster") or {}
            except Exception as exc:  # noqa: BLE001
                logger.warning("describe_cluster %s failed: %s", cname, exc)
                continue
            vpc_cfg = cluster.get("resourcesVpcConfig") or {}
            logging_cfg = (cluster.get("logging") or {}).get("clusterLogging") or []
            enabled_log_types: list[str] = []
            for entry in logging_cfg:
                if entry.get("enabled"):
                    enabled_log_types.extend(entry.get("types") or [])
            enc_cfg = cluster.get("encryptionConfig") or []
            secrets_kms = None
            for enc in enc_cfg:
                if "secrets" in (enc.get("resources") or []):
                    secrets_kms = (enc.get("provider") or {}).get("keyArn")
            snaps.append(
                self._snapshot(
                    resource_type="AWS::EKS::Cluster",
                    resource_name=cname,
                    region=self.region,
                    config={
                        "enabled_log_types": enabled_log_types,
                        "endpoint_public_access": vpc_cfg.get(
                            "endpointPublicAccess", True
                        ),
                        "public_access_cidrs": vpc_cfg.get("publicAccessCidrs") or [],
                        "secrets_kms_key_arn": secrets_kms,
                    },
                )
            )
        return snaps

    def _scan_ecr(self) -> list[ResourceSnapshot]:
        """Enumerate ECR repositories (tag immutability, scan-on-push)."""
        snaps: list[ResourceSnapshot] = []
        try:
            ecr = self._client("ecr")
            paginator = ecr.get_paginator("describe_repositories")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("describe_repositories failed: %s", exc)
            return snaps
        for page in pages:
            for repo in page.get("repositories") or []:
                name = repo.get("repositoryName") or ""
                scan_cfg = repo.get("imageScanningConfiguration") or {}
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::ECR::Repository",
                        resource_name=name,
                        region=self.region,
                        config={
                            "image_tag_mutability": repo.get("imageTagMutability"),
                            "scan_on_push": scan_cfg.get("scanOnPush", False),
                        },
                    )
                )
        return snaps

    def _scan_lambda(self) -> list[ResourceSnapshot]:
        """Enumerate Lambda functions (runtime, KMS, env vars, function URL auth)."""
        snaps: list[ResourceSnapshot] = []
        try:
            lam = self._client("lambda")
            paginator = lam.get_paginator("list_functions")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_functions failed: %s", exc)
            return snaps
        for page in pages:
            for fn in page.get("Functions") or []:
                name = fn.get("FunctionName") or ""
                env_vars = (fn.get("Environment") or {}).get("Variables") or {}
                url_cfg = None
                auth_type = None
                try:
                    url_cfg = lam.get_function_url_config(FunctionName=name)
                    auth_type = url_cfg.get("AuthType")
                except Exception:  # noqa: BLE001 - no URL configured
                    url_cfg = None
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::Lambda::Function",
                        resource_name=name,
                        region=self.region,
                        config={
                            "runtime": fn.get("Runtime"),
                            "kms_key_arn": fn.get("KMSKeyArn"),
                            "environment_variables": env_vars,
                            "function_url_config": url_cfg,
                            "auth_type": auth_type,
                        },
                    )
                )
        return snaps

    def _scan_dynamodb(self) -> list[ResourceSnapshot]:
        """Enumerate DynamoDB tables (encryption, point-in-time recovery)."""
        snaps: list[ResourceSnapshot] = []
        try:
            ddb = self._client("dynamodb")
            paginator = ddb.get_paginator("list_tables")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_tables failed: %s", exc)
            return snaps
        for page in pages:
            for tname in page.get("TableNames") or []:
                try:
                    table = ddb.describe_table(TableName=tname).get("Table") or {}
                except Exception:  # noqa: BLE001
                    continue
                pitr_enabled = False
                try:
                    cb = ddb.describe_continuous_backups(TableName=tname)
                    pitr = (
                        (cb.get("ContinuousBackupsDescription") or {})
                        .get("PointInTimeRecoveryDescription") or {}
                    )
                    pitr_enabled = (
                        pitr.get("PointInTimeRecoveryStatus") == "ENABLED"
                    )
                except Exception:  # noqa: BLE001
                    pitr_enabled = False
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::DynamoDB::Table",
                        resource_name=tname,
                        region=self.region,
                        config={
                            "sse_description": table.get("SSEDescription") or {},
                            "pitr_enabled": pitr_enabled,
                        },
                    )
                )
        return snaps

    def _scan_elbv2(self) -> list[ResourceSnapshot]:
        """Enumerate ALB/NLB load balancers (access logs, deletion protection)."""
        snaps: list[ResourceSnapshot] = []
        try:
            elb = self._client("elbv2")
            paginator = elb.get_paginator("describe_load_balancers")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("describe_load_balancers failed: %s", exc)
            return snaps
        for page in pages:
            for lb in page.get("LoadBalancers") or []:
                arn = lb.get("LoadBalancerArn") or ""
                name = lb.get("LoadBalancerName") or arn
                attrs: dict[str, str] = {}
                try:
                    raw_attrs = elb.describe_load_balancer_attributes(
                        LoadBalancerArn=arn
                    ).get("Attributes") or []
                    attrs = {a.get("Key"): a.get("Value") for a in raw_attrs}
                except Exception:  # noqa: BLE001
                    attrs = {}
                listeners: list[dict[str, Any]] = []
                try:
                    listeners = elb.describe_listeners(
                        LoadBalancerArn=arn
                    ).get("Listeners") or []
                except Exception:  # noqa: BLE001
                    listeners = []
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
                        resource_name=name,
                        region=self.region,
                        config={
                            "access_logs_enabled": attrs.get(
                                "access_logs.s3.enabled"
                            ) == "true",
                            "deletion_protection_enabled": attrs.get(
                                "deletion_protection.enabled"
                            ) == "true",
                            "listeners": listeners,
                        },
                    )
                )
        return snaps

    def _scan_kms(self) -> list[ResourceSnapshot]:
        """Enumerate customer-managed KMS keys (rotation, origin)."""
        snaps: list[ResourceSnapshot] = []
        try:
            kms = self._client("kms")
            paginator = kms.get_paginator("list_keys")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_keys failed: %s", exc)
            return snaps
        for page in pages:
            for key in page.get("Keys") or []:
                key_id = key.get("KeyId") or ""
                try:
                    meta = kms.describe_key(KeyId=key_id).get("KeyMetadata") or {}
                except Exception:  # noqa: BLE001
                    continue
                if meta.get("KeyManager") != "CUSTOMER":
                    continue
                rotation = False
                try:
                    rotation = kms.get_key_rotation_status(
                        KeyId=key_id
                    ).get("KeyRotationEnabled", False)
                except Exception:  # noqa: BLE001
                    rotation = False
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::KMS::Key",
                        resource_name=key_id,
                        region=self.region,
                        config={
                            "key_manager": meta.get("KeyManager"),
                            "origin": meta.get("Origin"),
                            "key_rotation_enabled": rotation,
                        },
                    )
                )
        return snaps

    def _scan_cloudtrail(self) -> list[ResourceSnapshot]:
        """Enumerate CloudTrail trails (multi-region, logging, validation)."""
        snaps: list[ResourceSnapshot] = []
        try:
            ct = self._client("cloudtrail")
            trails = ct.describe_trails().get("trailList") or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("describe_trails failed: %s", exc)
            return snaps
        for trail in trails:
            name = trail.get("Name") or ""
            arn = trail.get("TrailARN") or name
            is_logging = False
            try:
                is_logging = ct.get_trail_status(Name=arn).get("IsLogging", False)
            except Exception:  # noqa: BLE001
                is_logging = False
            snaps.append(
                self._snapshot(
                    resource_type="AWS::CloudTrail::Trail",
                    resource_name=name,
                    region=self.region,
                    config={
                        "is_logging": is_logging,
                        "is_multi_region_trail": trail.get(
                            "IsMultiRegionTrail", False
                        ),
                        "log_file_validation_enabled": trail.get(
                            "LogFileValidationEnabled", False
                        ),
                    },
                )
            )
        return snaps

    def _scan_elasticache(self) -> list[ResourceSnapshot]:
        """Enumerate ElastiCache replication groups (encryption at rest/transit)."""
        snaps: list[ResourceSnapshot] = []
        try:
            ec = self._client("elasticache")
            paginator = ec.get_paginator("describe_replication_groups")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("describe_replication_groups failed: %s", exc)
            return snaps
        for page in pages:
            for rg in page.get("ReplicationGroups") or []:
                name = rg.get("ReplicationGroupId") or ""
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::ElastiCache::ReplicationGroup",
                        resource_name=name,
                        region=self.region,
                        config={
                            "at_rest_encryption_enabled": rg.get(
                                "AtRestEncryptionEnabled", False
                            ),
                            "transit_encryption_enabled": rg.get(
                                "TransitEncryptionEnabled", False
                            ),
                        },
                    )
                )
        return snaps

    def _scan_apigateway(self) -> list[ResourceSnapshot]:
        """Enumerate API Gateway stages (logging level, WAF association)."""
        snaps: list[ResourceSnapshot] = []
        try:
            api = self._client("apigateway")
            apis = api.get_rest_apis().get("items") or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_rest_apis failed: %s", exc)
            return snaps
        for rest_api in apis:
            api_id = rest_api.get("id") or ""
            try:
                stages = api.get_stages(restApiId=api_id).get("item") or []
            except Exception:  # noqa: BLE001
                stages = []
            for stage in stages:
                stage_name = stage.get("stageName") or ""
                method_settings = stage.get("methodSettings") or {}
                logging_level = None
                for settings in method_settings.values():
                    if isinstance(settings, dict) and settings.get("loggingLevel"):
                        logging_level = settings.get("loggingLevel")
                        break
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::ApiGateway::Stage",
                        resource_name=f"{api_id}/{stage_name}",
                        region=self.region,
                        config={
                            "logging_level": logging_level,
                            "web_acl_arn": stage.get("webAclArn"),
                        },
                    )
                )
        return snaps

    def _scan_sns(self) -> list[ResourceSnapshot]:
        """Enumerate SNS topics (encryption key, access policy)."""
        snaps: list[ResourceSnapshot] = []
        try:
            sns = self._client("sns")
            paginator = sns.get_paginator("list_topics")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_topics failed: %s", exc)
            return snaps
        for page in pages:
            for topic in page.get("Topics") or []:
                arn = topic.get("TopicArn") or ""
                name = arn.split(":")[-1] if arn else ""
                try:
                    attrs = sns.get_topic_attributes(
                        TopicArn=arn
                    ).get("Attributes") or {}
                except Exception:  # noqa: BLE001
                    attrs = {}
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::SNS::Topic",
                        resource_name=name,
                        region=self.region,
                        config={
                            "kms_master_key_id": attrs.get("KmsMasterKeyId"),
                            "policy": attrs.get("Policy"),
                        },
                    )
                )
        return snaps

    def _scan_sqs(self) -> list[ResourceSnapshot]:
        """Enumerate SQS queues (encryption, access policy)."""
        snaps: list[ResourceSnapshot] = []
        try:
            sqs = self._client("sqs")
            urls = sqs.list_queues().get("QueueUrls") or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_queues failed: %s", exc)
            return snaps
        for url in urls:
            name = url.rsplit("/", 1)[-1]
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=url, AttributeNames=["All"]
                ).get("Attributes") or {}
            except Exception:  # noqa: BLE001
                attrs = {}
            snaps.append(
                self._snapshot(
                    resource_type="AWS::SQS::Queue",
                    resource_name=name,
                    region=self.region,
                    config={
                        "kms_master_key_id": attrs.get("KmsMasterKeyId"),
                        "policy": attrs.get("Policy"),
                        "sqs_managed_sse_enabled": str(
                            attrs.get("SqsManagedSseEnabled", "false")
                        ).lower() == "true",
                    },
                )
            )
        return snaps

    def _scan_secrets(self) -> list[ResourceSnapshot]:
        """Enumerate Secrets Manager secrets (rotation enabled)."""
        snaps: list[ResourceSnapshot] = []
        try:
            sm = self._client("secretsmanager")
            paginator = sm.get_paginator("list_secrets")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_secrets failed: %s", exc)
            return snaps
        for page in pages:
            for secret in page.get("SecretList") or []:
                name = secret.get("Name") or ""
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::SecretsManager::Secret",
                        resource_name=name,
                        region=self.region,
                        config={
                            "rotation_enabled": secret.get("RotationEnabled", False),
                        },
                    )
                )
        return snaps

    def _scan_acm(self) -> list[ResourceSnapshot]:
        """Enumerate ACM certificates (days to expiry)."""
        from datetime import datetime, timezone

        snaps: list[ResourceSnapshot] = []
        try:
            acm = self._client("acm")
            paginator = acm.get_paginator("list_certificates")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("list_certificates failed: %s", exc)
            return snaps
        now = datetime.now(timezone.utc)
        for page in pages:
            for cert in page.get("CertificateSummaryList") or []:
                arn = cert.get("CertificateArn") or ""
                domain = cert.get("DomainName") or arn
                days_to_expiry = None
                try:
                    detail = acm.describe_certificate(
                        CertificateArn=arn
                    ).get("Certificate") or {}
                    not_after = detail.get("NotAfter")
                    if isinstance(not_after, datetime):
                        if not_after.tzinfo is None:
                            not_after = not_after.replace(tzinfo=timezone.utc)
                        days_to_expiry = (not_after - now).days
                except Exception:  # noqa: BLE001
                    days_to_expiry = None
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::CertificateManager::Certificate",
                        resource_name=domain,
                        region=self.region,
                        config={"days_to_expiry": days_to_expiry},
                    )
                )
        return snaps

    def _scan_log_groups(self) -> list[ResourceSnapshot]:
        """Enumerate CloudWatch log groups (encryption, retention)."""
        snaps: list[ResourceSnapshot] = []
        try:
            logs = self._client("logs")
            paginator = logs.get_paginator("describe_log_groups")
            pages = paginator.paginate()
        except Exception as exc:  # noqa: BLE001
            logger.warning("describe_log_groups failed: %s", exc)
            return snaps
        for page in pages:
            for lg in page.get("logGroups") or []:
                name = lg.get("logGroupName") or ""
                snaps.append(
                    self._snapshot(
                        resource_type="AWS::Logs::LogGroup",
                        resource_name=name,
                        region=self.region,
                        config={
                            "kms_key_id": lg.get("kmsKeyId"),
                            "retention_in_days": lg.get("retentionInDays"),
                        },
                    )
                )
        return snaps

    def _scan_config_recorders(self) -> list[ResourceSnapshot]:
        """Enumerate AWS Config recorders (recording state, coverage)."""
        snaps: list[ResourceSnapshot] = []
        try:
            cfg = self._client("config")
            recorders = cfg.describe_configuration_recorders().get(
                "ConfigurationRecorders"
            ) or []
            statuses = cfg.describe_configuration_recorder_status().get(
                "ConfigurationRecordersStatus"
            ) or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("describe_configuration_recorders failed: %s", exc)
            return snaps
        status_map = {s.get("name"): s for s in statuses}
        for rec in recorders:
            name = rec.get("name") or ""
            group = rec.get("recordingGroup") or {}
            status = status_map.get(name) or {}
            snaps.append(
                self._snapshot(
                    resource_type="AWS::Config::ConfigurationRecorder",
                    resource_name=name,
                    region=self.region,
                    config={
                        "all_supported": group.get("allSupported", False),
                        "recording": status.get("recording", False),
                    },
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
                *self._scan_vpcs(),
                *self._scan_rds(),
                *self._scan_eks(),
                *self._scan_ecr(),
                *self._scan_lambda(),
                *self._scan_dynamodb(),
                *self._scan_elbv2(),
                *self._scan_kms(),
                *self._scan_cloudtrail(),
                *self._scan_elasticache(),
                *self._scan_apigateway(),
                *self._scan_sns(),
                *self._scan_sqs(),
                *self._scan_secrets(),
                *self._scan_acm(),
                *self._scan_log_groups(),
                *self._scan_config_recorders(),
            ]

        snapshots, self._policy_findings = await asyncio.gather(
            asyncio.to_thread(_collect),
            self._policy_adapter.fetch_findings(),
        )
        logger.info(
            "AWS scan returned %d snapshots, %d policy finding(s)",
            len(snapshots),
            len(self._policy_findings),
        )
        return snapshots

    async def fetch_policy_findings(self) -> list[FindingResult]:
        """Fetch AWS policy compliance findings on demand."""
        self._policy_findings = await self._policy_adapter.fetch_findings()
        return self._policy_findings

    @property
    def policy_findings(self) -> list[FindingResult]:
        """Policy compliance findings from the most recent scan."""
        return self._policy_findings

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




