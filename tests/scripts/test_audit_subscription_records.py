"""Unit tests for scripts/audit_subscription_records.py classify()."""

from __future__ import annotations

from datetime import datetime, timezone

from cloudguardiq.core.enums import CloudProvider
from cloudguardiq.subscriptions.repository import SubscriptionRecord
from scripts.audit_subscription_records import classify


def _rec(**kw) -> SubscriptionRecord:
    defaults: dict = {
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "subscription_id": "11111111-1111-1111-1111-111111111111",
        "customer_tenant_id": "00000000-0000-0000-0000-000000000001",
        "display_name": "test",
        "provider": CloudProvider.AZURE,
        "state": "Enabled",
        "added_at": datetime.now(timezone.utc),
    }
    defaults.update(kw)
    return SubscriptionRecord(**defaults)


def test_healthy_azure() -> None:
    assert classify(_rec()) == []


def test_healthy_aws() -> None:
    rec = _rec(
        provider=CloudProvider.AWS,
        subscription_id="123456789012",
        aws_account_id="123456789012",
        aws_region="us-east-1",
    )
    assert classify(rec) == []


def test_healthy_gcp() -> None:
    rec = _rec(
        provider=CloudProvider.GCP,
        subscription_id="my-cool-project",
        gcp_project_id="my-cool-project",
    )
    assert classify(rec) == []


def test_aws_missing_account_id() -> None:
    rec = _rec(
        provider=CloudProvider.AWS,
        subscription_id="123456789012",
        aws_account_id="",
        aws_region="us-east-1",
    )
    issues = classify(rec)
    assert any("aws_account_id is empty" in i for i in issues)


def test_aws_missing_region() -> None:
    rec = _rec(
        provider=CloudProvider.AWS,
        subscription_id="123456789012",
        aws_account_id="123456789012",
        aws_region="",
    )
    issues = classify(rec)
    assert any("aws_region is empty" in i for i in issues)


def test_azure_carrying_aws_account_id() -> None:
    rec = _rec(subscription_id="123456789012")
    issues = classify(rec)
    assert any("12-digit AWS account" in i for i in issues)


def test_gcp_missing_project_id() -> None:
    rec = _rec(
        provider=CloudProvider.GCP,
        subscription_id="my-cool-project",
        gcp_project_id="",
    )
    issues = classify(rec)
    assert any("gcp_project_id is empty" in i for i in issues)


def test_aws_account_id_mismatch() -> None:
    rec = _rec(
        provider=CloudProvider.AWS,
        subscription_id="123456789012",
        aws_account_id="999999999999",
        aws_region="us-east-1",
    )
    issues = classify(rec)
    assert any("does not match aws_account_id" in i for i in issues)
