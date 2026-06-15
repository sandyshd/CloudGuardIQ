"""Tests for AWSAdapter Phase 2 expanded collectors — boto3 fully mocked."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from cloudguardiq.adapters.aws.adapter import AWSAdapter
from cloudguardiq.policy.engine import PolicyEngine


def _paginated(key: str, items: list[dict[str, Any]]) -> MagicMock:
    p = MagicMock()
    p.paginate.return_value = [{key: items}]
    return p


def _fake_session() -> MagicMock:
    """Fake boto3.Session exercising every Phase 2 collector."""
    session = MagicMock(name="Session")
    now = datetime.now(timezone.utc)

    # --- ec2 (vpcs + flow logs); other ec2 paginators empty ---
    ec2 = MagicMock(name="ec2")
    ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1", "Tags": []}]}
    ec2.describe_flow_logs.return_value = {"FlowLogs": []}
    ec2.describe_addresses.return_value = {"Addresses": []}
    ec2.get_paginator.side_effect = lambda op: _paginated(
        {
            "describe_volumes": "Volumes",
            "describe_instances": "Reservations",
            "describe_security_groups": "SecurityGroups",
        }.get(op, "Items"),
        [],
    )

    # --- iam ---
    iam = MagicMock(name="iam")
    iam.get_account_summary.return_value = {"SummaryMap": {}}
    iam.get_account_password_policy.return_value = {
        "PasswordPolicy": {
            "MinimumPasswordLength": 8,
            "RequireSymbols": False,
            "RequireNumbers": False,
            "PasswordReusePrevention": 0,
        }
    }
    iam.get_paginator.return_value = _paginated(
        "Users", [{"UserName": "bob", "UserId": "u1", "Arn": "arn", "PasswordLastUsed": "x"}]
    )
    iam.list_mfa_devices.return_value = {"MFADevices": []}
    iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "AKIA1",
                "Status": "Active",
                "CreateDate": now - timedelta(days=200),
            }
        ]
    }

    # --- rds ---
    rds = MagicMock(name="rds")
    rds.get_paginator.return_value = _paginated(
        "DBInstances",
        [
            {
                "DBInstanceIdentifier": "db-1",
                "StorageEncrypted": False,
                "PubliclyAccessible": True,
                "BackupRetentionPeriod": 0,
                "Engine": "postgres",
            }
        ],
    )

    # --- eks ---
    eks = MagicMock(name="eks")
    eks.list_clusters.return_value = {"clusters": ["k1"]}
    eks.describe_cluster.return_value = {
        "cluster": {
            "resourcesVpcConfig": {
                "endpointPublicAccess": True,
                "publicAccessCidrs": ["0.0.0.0/0"],
            },
            "logging": {"clusterLogging": [{"enabled": False, "types": ["audit"]}]},
            "encryptionConfig": [],
        }
    }

    # --- ecr ---
    ecr = MagicMock(name="ecr")
    ecr.get_paginator.return_value = _paginated(
        "repositories",
        [
            {
                "repositoryName": "repo-1",
                "imageTagMutability": "MUTABLE",
                "imageScanningConfiguration": {"scanOnPush": False},
            }
        ],
    )

    # --- lambda ---
    lam = MagicMock(name="lambda")
    lam.get_paginator.return_value = _paginated(
        "Functions",
        [
            {
                "FunctionName": "fn-1",
                "Runtime": "python3.8",
                "KMSKeyArn": None,
                "Environment": {"Variables": {"DB_PASSWORD": "secret"}},
            }
        ],
    )
    lam.get_function_url_config.return_value = {"AuthType": "NONE"}

    # --- dynamodb ---
    ddb = MagicMock(name="dynamodb")
    ddb.get_paginator.return_value = _paginated("TableNames", ["t-1"])
    ddb.describe_table.return_value = {"Table": {"SSEDescription": {}}}
    ddb.describe_continuous_backups.return_value = {
        "ContinuousBackupsDescription": {
            "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "DISABLED"}
        }
    }

    # --- elbv2 ---
    elb = MagicMock(name="elbv2")
    elb.get_paginator.return_value = _paginated(
        "LoadBalancers",
        [{"LoadBalancerArn": "arn:lb", "LoadBalancerName": "lb-1"}],
    )
    elb.describe_load_balancer_attributes.return_value = {
        "Attributes": [
            {"Key": "access_logs.s3.enabled", "Value": "false"},
            {"Key": "deletion_protection.enabled", "Value": "false"},
        ]
    }
    elb.describe_listeners.return_value = {"Listeners": []}

    # --- kms ---
    kms = MagicMock(name="kms")
    kms.get_paginator.return_value = _paginated("Keys", [{"KeyId": "key-1"}])
    kms.describe_key.return_value = {
        "KeyMetadata": {"KeyManager": "CUSTOMER", "Origin": "AWS_KMS"}
    }
    kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}

    # --- cloudtrail ---
    ct = MagicMock(name="cloudtrail")
    ct.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "trail-1",
                "TrailARN": "arn:trail",
                "IsMultiRegionTrail": False,
                "LogFileValidationEnabled": False,
            }
        ]
    }
    ct.get_trail_status.return_value = {"IsLogging": True}

    # --- elasticache ---
    ec = MagicMock(name="elasticache")
    ec.get_paginator.return_value = _paginated(
        "ReplicationGroups",
        [
            {
                "ReplicationGroupId": "rg-1",
                "AtRestEncryptionEnabled": False,
                "TransitEncryptionEnabled": False,
            }
        ],
    )

    # --- apigateway ---
    api = MagicMock(name="apigateway")
    api.get_rest_apis.return_value = {"items": [{"id": "api-1"}]}
    api.get_stages.return_value = {
        "item": [{"stageName": "prod", "methodSettings": {}, "webAclArn": None}]
    }

    # --- sns ---
    sns = MagicMock(name="sns")
    sns.get_paginator.return_value = _paginated(
        "Topics", [{"TopicArn": "arn:aws:sns:us-east-1:1:topic-1"}]
    )
    sns.get_topic_attributes.return_value = {"Attributes": {"KmsMasterKeyId": None}}

    # --- sqs ---
    sqs = MagicMock(name="sqs")
    sqs.list_queues.return_value = {"QueueUrls": ["https://sqs/q-1"]}
    sqs.get_queue_attributes.return_value = {
        "Attributes": {"KmsMasterKeyId": None, "SqsManagedSseEnabled": "false"}
    }

    # --- secretsmanager ---
    sm = MagicMock(name="secretsmanager")
    sm.get_paginator.return_value = _paginated(
        "SecretList", [{"Name": "sec-1", "RotationEnabled": False}]
    )

    # --- acm ---
    acm = MagicMock(name="acm")
    acm.get_paginator.return_value = _paginated(
        "CertificateSummaryList",
        [{"CertificateArn": "arn:cert", "DomainName": "example.com"}],
    )
    acm.describe_certificate.return_value = {
        "Certificate": {"NotAfter": now + timedelta(days=10)}
    }

    # --- logs ---
    logs = MagicMock(name="logs")
    logs.get_paginator.return_value = _paginated(
        "logGroups", [{"logGroupName": "lg-1", "kmsKeyId": None, "retentionInDays": None}]
    )

    # --- config ---
    config = MagicMock(name="config")
    config.describe_configuration_recorders.return_value = {
        "ConfigurationRecorders": [
            {"name": "default", "recordingGroup": {"allSupported": False}}
        ]
    }
    config.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": [{"name": "default", "recording": False}]
    }

    sts = MagicMock(name="sts")
    sts.get_caller_identity.return_value = {"Account": "111122223333"}

    clients = {
        "ec2": ec2, "iam": iam, "rds": rds, "eks": eks, "ecr": ecr,
        "lambda": lam, "dynamodb": ddb, "elbv2": elb, "kms": kms,
        "cloudtrail": ct, "elasticache": ec, "apigateway": api, "sns": sns,
        "sqs": sqs, "secretsmanager": sm, "acm": acm, "logs": logs,
        "config": config, "sts": sts, "s3": MagicMock(name="s3"),
    }
    clients["s3"].list_buckets.return_value = {"Buckets": []}
    session.client.side_effect = lambda name: clients[name]
    return session


@pytest.mark.asyncio
async def test_phase2_collectors_emit_expected_types() -> None:
    adapter = AWSAdapter(
        account_id="111122223333", region="us-east-1", session=_fake_session()
    )
    snaps = await adapter.scan()
    types = {s.resource_type for s in snaps}
    expected = {
        "AWS::EC2::VPC",
        "AWS::RDS::DBInstance",
        "AWS::EKS::Cluster",
        "AWS::ECR::Repository",
        "AWS::Lambda::Function",
        "AWS::DynamoDB::Table",
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "AWS::KMS::Key",
        "AWS::CloudTrail::Trail",
        "AWS::ElastiCache::ReplicationGroup",
        "AWS::ApiGateway::Stage",
        "AWS::SNS::Topic",
        "AWS::SQS::Queue",
        "AWS::SecretsManager::Secret",
        "AWS::CertificateManager::Certificate",
        "AWS::Logs::LogGroup",
        "AWS::Config::ConfigurationRecorder",
        "AWS::IAM::PasswordPolicy",
    }
    assert expected <= types


@pytest.mark.asyncio
async def test_phase2_snapshots_produce_findings() -> None:
    adapter = AWSAdapter(
        account_id="111122223333", region="us-east-1", session=_fake_session()
    )
    snaps = await adapter.scan()
    findings = PolicyEngine().evaluate(snaps)
    fired = {f.rule_id for f in findings}
    # Representative findings across the new resource types.
    assert any(rid.startswith("AWS-RDS") for rid in fired)
    assert any(rid.startswith("AWS-KMS") for rid in fired)
    assert any(rid.startswith("AWS-CT") or "CLOUDTRAIL" in rid.upper() for rid in fired)
    assert "AWS-IAM-003" in fired
    assert "AWS-IAM-004" in fired


@pytest.mark.asyncio
async def test_phase2_config_keys_match_rule_contract() -> None:
    adapter = AWSAdapter(
        account_id="111122223333", region="us-east-1", session=_fake_session()
    )
    snaps = await adapter.scan()
    by_type = {s.resource_type: s for s in snaps}

    rds = by_type["AWS::RDS::DBInstance"].config
    assert {"storage_encrypted", "publicly_accessible", "backup_retention_period"} <= set(rds)

    lam = by_type["AWS::Lambda::Function"].config
    assert {"runtime", "kms_key_arn", "environment_variables", "auth_type"} <= set(lam)

    kms = by_type["AWS::KMS::Key"].config
    assert {"key_manager", "origin", "key_rotation_enabled"} <= set(kms)
