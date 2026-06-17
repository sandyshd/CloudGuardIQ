"""Verify scan persistence stamps tenant_id from JWT (regression).

Bug: 2026-04-29 -- POST /scan returned 130 findings inline but the
dashboard's subsequent GET /findings returned []. Cause: snapshots and
findings were saved with tenant_id="" while the GET filters by the
JWT's tid claim.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.api.main import app
from cloudguardiq.core.config import get_settings
from cloudguardiq.core.enums import DataTier
from cloudguardiq.core.models import ResourceSnapshot


@pytest.fixture
async def authed_client(monkeypatch) -> AsyncClient:
    # Re-enable auth so the handler runs the tenant_id stamping branch,
    # then inject a deterministic TokenPayload via dependency_overrides.
    monkeypatch.delenv("CLOUDGUARDIQ_AUTH_DISABLED", raising=False)
    monkeypatch.setenv("CLOUDGUARDIQ_AUTH_DISABLED", "false")
    get_settings.cache_clear()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid="tenant-stamp-test"
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_scan_stamps_tenant_id_on_persisted_findings(
    authed_client: AsyncClient,
) -> None:
    """save_finding must receive findings with tenant_id from the JWT."""
    sub_id = "11111111-1111-1111-1111-111111111111"

    snap = ResourceSnapshot(
        subscription_id=sub_id,
        resource_group="rg1",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="sa-insecure",
        region="eastus",
        data_tier=DataTier.TIER1_NATIVE,
        config={"supportsHttpsTrafficOnly": False, "allowBlobPublicAccess": True},
    )

    mock_repo = AsyncMock()
    mock_repo.save_snapshot = AsyncMock(return_value="snap-id")
    mock_repo.save_finding = AsyncMock(return_value="finding-id")
    mock_repo.save_scan_result = AsyncMock()
    # Subscription ownership check passes for this tenant.
    mock_repo.get_subscription = AsyncMock(
        return_value={"subscription_id": sub_id, "tenant_id": "tenant-stamp-test"}
    )

    mock_adapter = AsyncMock()
    mock_adapter.scan = AsyncMock(return_value=[snap])
    mock_adapter.policy_findings = []
    mock_adapter.defender_findings = []
    mock_adapter.securityhub_findings = []
    mock_adapter.scc_findings = []

    # Bypass tenant ownership validation -- the handler calls a private
    # helper which we don't need to stand up against a real Cosmos DB.
    async def _allow_owned(_user, sub):
        return sub.lower()

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch(
            "cloudguardiq.pipeline.scan_pipeline.refresh_prices",
            new=AsyncMock(),
        ),
        patch(
            "cloudguardiq.api.main._validate_owned_subscription",
            new=_allow_owned,
        ),
        patch(
            "azure.identity.DefaultAzureCredential",
            return_value=MagicMock(),
        ),
        patch(
            "cloudguardiq.api.main.AzureAdapter",
            return_value=mock_adapter,
        ),
    ):
        r = await authed_client.post("/scan", json={"subscription_id": sub_id})

    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] >= 1

    # Every persisted snapshot carries the JWT tenant.
    assert mock_repo.save_snapshot.call_count >= 1
    for call in mock_repo.save_snapshot.call_args_list:
        persisted_snap = call.args[0]
        assert persisted_snap.tenant_id == "tenant-stamp-test"

    # Every persisted finding carries the JWT tenant -- including the
    # nested resource_snapshot, which is what the GET filter inspects.
    assert mock_repo.save_finding.call_count >= 1
    for call in mock_repo.save_finding.call_args_list:
        persisted_finding = call.args[0]
        assert persisted_finding.tenant_id == "tenant-stamp-test"
        # resource_snapshot may be None for rule outputs that did not
        # carry the snapshot through; the persistence layer reads the
        # finding-level tenant_id first so that path is the only one
        # we strictly need to assert.
        if persisted_finding.resource_snapshot is not None:
            assert persisted_finding.resource_snapshot.tenant_id == "tenant-stamp-test"

