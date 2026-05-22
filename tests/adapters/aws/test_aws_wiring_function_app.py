"""Tests for the multi-cloud SubscriptionRecord schema and function_app wiring."""

from __future__ import annotations

import importlib.util
from unittest.mock import MagicMock, patch

import pytest

from cloudguardiq.adapters.aws.adapter import AWSAdapter
from cloudguardiq.core.enums import CloudProvider
from cloudguardiq.subscriptions.repository import SubscriptionRecord

_HAS_FUNCTIONS = importlib.util.find_spec("azure.functions") is not None
_needs_functions = pytest.mark.skipif(not _HAS_FUNCTIONS, reason="azure-functions not installed")


# ---------------------------------------------------------------------------
# SubscriptionRecord schema -- new provider/aws_account_id/aws_region fields
# ---------------------------------------------------------------------------


class TestSubscriptionRecordMultiCloud:
    def test_defaults_to_azure_for_backward_compat(self) -> None:
        rec = SubscriptionRecord(tenant_id="t1", subscription_id="sub-1")
        assert rec.provider is CloudProvider.AZURE
        assert rec.aws_account_id == ""
        assert rec.aws_region == ""

    def test_aws_record_roundtrip(self) -> None:
        original = SubscriptionRecord(
            tenant_id="t1",
            subscription_id="111122223333",
            provider=CloudProvider.AWS,
            aws_account_id="111122223333",
            aws_region="us-west-2",
            display_name="Prod AWS account",
        )
        doc = original.to_document()
        assert doc["provider"] == "AWS"
        assert doc["aws_account_id"] == "111122223333"
        assert doc["aws_region"] == "us-west-2"

        restored = SubscriptionRecord.from_document(doc)
        assert restored.provider is CloudProvider.AWS
        assert restored.aws_account_id == "111122223333"
        assert restored.aws_region == "us-west-2"
        assert restored.subscription_id == "111122223333"

    def test_legacy_document_without_provider_falls_back_to_azure(self) -> None:
        """Pre-existing Cosmos rows have no ``provider`` field."""
        legacy = {
            "id": "t1:sub-1",
            "tenant_id": "t1",
            "subscription_id": "sub-1",
            "customer_tenant_id": "t1",
            "display_name": "",
            "state": "Enabled",
            "added_at": "2026-01-01T00:00:00+00:00",
            "last_scan_at": None,
            "removed_at": None,
        }
        rec = SubscriptionRecord.from_document(legacy)
        assert rec.provider is CloudProvider.AZURE
        assert rec.aws_account_id == ""

    def test_unknown_provider_value_falls_back_to_azure(self) -> None:
        doc = {
            "tenant_id": "t1",
            "subscription_id": "sub-1",
            "provider": "MARS",
        }
        rec = SubscriptionRecord.from_document(doc)
        assert rec.provider is CloudProvider.AZURE


# ---------------------------------------------------------------------------
# _build_scan_pipeline -- provider switch picks the right adapter
# ---------------------------------------------------------------------------


@_needs_functions
@pytest.mark.asyncio
async def test_build_scan_pipeline_aws_routes_through_aws_adapter() -> None:
    """provider=AWS must produce a pipeline whose adapter is AWSAdapter,
    without invoking any Azure credential chain."""
    import function_app

    db = MagicMock()
    db._db = MagicMock()
    async_credential = MagicMock()

    # Patch boto3 import inside AWSAdapter.scan path to avoid network.
    # AWSAdapter doesn't touch boto3 at __init__ when a session is passed,
    # but here we only build the pipeline -- no scan -- so default
    # construction is fine.
    pipeline = await function_app._build_scan_pipeline(
        "111122223333",
        db,
        async_credential,
        provider="AWS",
        aws_account_id="111122223333",
        aws_region="us-west-2",
    )

    assert isinstance(pipeline.adapter, AWSAdapter)
    assert pipeline.adapter.account_id == "111122223333"
    assert pipeline.adapter.region == "us-west-2"


@_needs_functions
@pytest.mark.asyncio
async def test_build_scan_pipeline_azure_default_still_works() -> None:
    """provider omitted -> Azure path uses build_scan_adapter with AzureAdapter."""
    import function_app

    db = MagicMock()
    db._db = MagicMock()
    async_credential = MagicMock()

    with patch(
        "azure.identity.DefaultAzureCredential", return_value=MagicMock()
    ):
        pipeline = await function_app._build_scan_pipeline(
            "sub-abc",
            db,
            async_credential,
        )

    # AzureAdapter import is lazy inside the factory; assert by class name to
    # avoid a heavy import at the top of this test module.
    assert pipeline.adapter.__class__.__name__ == "AzureAdapter"
