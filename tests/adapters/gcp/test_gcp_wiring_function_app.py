"""Tests for SubscriptionRecord GCP fields and function_app GCP wiring."""

from __future__ import annotations

import importlib.util
from unittest.mock import MagicMock

import pytest

from cloudguardiq.adapters.gcp.adapter import GCPAdapter
from cloudguardiq.core.enums import CloudProvider
from cloudguardiq.subscriptions.repository import SubscriptionRecord

_HAS_FUNCTIONS = importlib.util.find_spec("azure.functions") is not None
_needs_functions = pytest.mark.skipif(
    not _HAS_FUNCTIONS, reason="azure-functions not installed"
)


# ---------------------------------------------------------------------------
# SubscriptionRecord GCP field round-trip
# ---------------------------------------------------------------------------


class TestSubscriptionRecordGCP:
    """The new ``gcp_project_id`` field must round-trip through Cosmos docs."""

    def test_defaults_keep_gcp_project_empty(self) -> None:
        """Azure / unspecified records should never carry a GCP project."""
        rec = SubscriptionRecord(tenant_id="t1", subscription_id="sub-1")
        assert rec.provider is CloudProvider.AZURE
        assert rec.gcp_project_id == ""

    def test_gcp_record_roundtrip(self) -> None:
        """A GCP record serialised to Cosmos and back retains its identity."""
        original = SubscriptionRecord(
            tenant_id="t1",
            subscription_id="my-proj-123",
            provider=CloudProvider.GCP,
            gcp_project_id="my-proj-123",
            display_name="Prod GCP project",
        )
        doc = original.to_document()
        assert doc["provider"] == "GCP"
        assert doc["gcp_project_id"] == "my-proj-123"

        restored = SubscriptionRecord.from_document(doc)
        assert restored.provider is CloudProvider.GCP
        assert restored.gcp_project_id == "my-proj-123"
        assert restored.subscription_id == "my-proj-123"

    def test_legacy_document_has_empty_gcp_project(self) -> None:
        """Pre-existing rows lack ``gcp_project_id`` -- must default cleanly."""
        legacy = {
            "tenant_id": "t1",
            "subscription_id": "sub-1",
            "provider": "AZURE",
        }
        rec = SubscriptionRecord.from_document(legacy)
        assert rec.gcp_project_id == ""


# ---------------------------------------------------------------------------
# _build_scan_pipeline -- provider switch picks the GCP adapter
# ---------------------------------------------------------------------------


@_needs_functions
@pytest.mark.asyncio
async def test_build_scan_pipeline_gcp_routes_through_gcp_adapter() -> None:
    """provider=GCP must produce a pipeline whose adapter is GCPAdapter,
    without invoking any Azure credential chain."""
    import function_app

    db = MagicMock()
    db._db = MagicMock()
    async_credential = MagicMock()

    pipeline = await function_app._build_scan_pipeline(
        "my-proj-123",
        db,
        async_credential,
        provider="GCP",
        gcp_project_id="my-proj-123",
    )

    assert isinstance(pipeline.adapter, GCPAdapter)
    assert pipeline.adapter.project_id == "my-proj-123"


@_needs_functions
@pytest.mark.asyncio
async def test_build_scan_pipeline_gcp_requires_project_id() -> None:
    """Missing gcp_project_id surfaces as a clear RuntimeError at build time."""
    import function_app

    db = MagicMock()
    db._db = MagicMock()
    async_credential = MagicMock()

    with pytest.raises(RuntimeError, match="missing gcp_project_id"):
        await function_app._build_scan_pipeline(
            "my-proj-123",
            db,
            async_credential,
            provider="GCP",
            gcp_project_id="",
        )


# ---------------------------------------------------------------------------
# Onboarding mirror -- GCP connect writes a SubscriptionRecord
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mirror_gcp_project_creates_subscription_record(
    monkeypatch,
) -> None:
    """``_mirror_gcp_project_for_operator`` must upsert a GCP-shaped
    SubscriptionRecord into the operator-tenant container so the timer
    picks it up on the next tick."""
    from cloudguardiq.api import onboarding_v1

    captured: list[SubscriptionRecord] = []

    class _StubRepo:
        async def get(self, tenant_id: str, sub_id: str) -> SubscriptionRecord | None:
            return None

        async def upsert(self, rec: SubscriptionRecord) -> None:
            captured.append(rec)

    monkeypatch.setattr(
        onboarding_v1.subscriptions_module,
        "_get_repo",
        lambda: _StubRepo(),
    )

    fake_user = MagicMock()
    fake_user.tenant_id = "operator-tenant"
    fake_user.tid = "operator-tenant"
    monkeypatch.setattr(
        onboarding_v1, "get_tenant_id", lambda _u: "operator-tenant"
    )

    await onboarding_v1._mirror_gcp_project_for_operator(
        user=fake_user,
        project_id="my-proj-456",
    )

    assert len(captured) == 1
    rec = captured[0]
    assert rec.provider is CloudProvider.GCP
    assert rec.gcp_project_id == "my-proj-456"
    assert rec.subscription_id == "my-proj-456"
    assert rec.tenant_id == "operator-tenant"


@pytest.mark.asyncio
async def test_mirror_gcp_project_restores_removed_record(monkeypatch) -> None:
    """Re-connecting a previously-removed GCP project should flip state
    back to Enabled rather than ignore the request."""
    from cloudguardiq.api import onboarding_v1

    existing = SubscriptionRecord(
        tenant_id="operator-tenant",
        subscription_id="my-proj-789",
        provider=CloudProvider.GCP,
        gcp_project_id="my-proj-789",
        state="Removed",
    )
    upserts: list[SubscriptionRecord] = []

    class _StubRepo:
        async def get(self, tenant_id: str, sub_id: str) -> SubscriptionRecord:
            return existing

        async def upsert(self, rec: SubscriptionRecord) -> None:
            upserts.append(rec)

    monkeypatch.setattr(
        onboarding_v1.subscriptions_module,
        "_get_repo",
        lambda: _StubRepo(),
    )
    monkeypatch.setattr(
        onboarding_v1, "get_tenant_id", lambda _u: "operator-tenant"
    )

    await onboarding_v1._mirror_gcp_project_for_operator(
        user=MagicMock(),
        project_id="my-proj-789",
    )

    assert len(upserts) == 1
    assert upserts[0].state == "Enabled"
    assert upserts[0].removed_at is None
    assert upserts[0].provider is CloudProvider.GCP
