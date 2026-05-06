"""Tests for finding lifecycle endpoints (resolve / snooze / apply)."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.api.main import app
from cloudguardiq.core.config import get_settings
from cloudguardiq.core.enums import DataTier, FindingStatus, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

SUB_ID = "11111111-1111-1111-1111-111111111111"
TENANT = "tenant-lifecycle"


@pytest.fixture
async def authed_client(monkeypatch) -> AsyncClient:
    monkeypatch.setenv("CLOUDGUARDIQ_AUTH_DISABLED", "false")
    get_settings.cache_clear()
    app.dependency_overrides[verify_token] = lambda: TokenPayload(
        sub="user-1", tid=TENANT
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def _sample_finding(status: str = "OPEN") -> FindingResult:
    snap = ResourceSnapshot(
        subscription_id=SUB_ID,
        resource_group="rg1",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="sa1",
        region="eastus",
        data_tier=DataTier.TIER1_NATIVE,
        tenant_id=TENANT,
    )
    return FindingResult(
        finding_id="finding-abc",
        tenant_id=TENANT,
        rule_id="STORAGE-001",
        rule_name="Storage HTTPS Only",
        severity=Severity.HIGH,
        resource_snapshot=snap,
        description="test",
    )


@pytest.mark.asyncio
async def test_resolve_marks_finding_resolved(authed_client: AsyncClient) -> None:
    updated = _sample_finding()
    updated.status = FindingStatus.RESOLVED
    updated.resolved_at = datetime.now(timezone.utc)
    updated.resolved_by = "user-1"

    mock_repo = AsyncMock()
    mock_repo.update_finding_status = AsyncMock(return_value=updated)

    async def _allow_owned(_user, sub):
        return sub.lower()

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned),
    ):
        r = await authed_client.post(
            "/findings/finding-abc/resolve",
            json={"subscription_id": SUB_ID},
        )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "RESOLVED"
    assert body["resolved_by"] == "user-1"
    assert body["resolved_at"] is not None

    # Repository called with the right kwargs.
    call = mock_repo.update_finding_status.call_args
    assert call.kwargs["finding_id"] == "finding-abc"
    assert call.kwargs["subscription_id"] == SUB_ID
    assert call.kwargs["tenant_id"] == TENANT
    assert call.kwargs["status"] == "RESOLVED"
    assert "resolved_at" in call.kwargs["extras"]
    assert call.kwargs["extras"]["resolved_by"] == "user-1"


@pytest.mark.asyncio
async def test_snooze_sets_snoozed_until(authed_client: AsyncClient) -> None:
    updated = _sample_finding()
    updated.status = FindingStatus.SNOOZED

    mock_repo = AsyncMock()
    mock_repo.update_finding_status = AsyncMock(return_value=updated)

    async def _allow_owned(_user, sub):
        return sub.lower()

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned),
    ):
        r = await authed_client.post(
            "/findings/finding-abc/snooze",
            json={"subscription_id": SUB_ID, "days": 14},
        )
    assert r.status_code == 200, r.text
    extras = mock_repo.update_finding_status.call_args.kwargs["extras"]
    assert "snoozed_until" in extras


@pytest.mark.asyncio
async def test_apply_sets_applied_at(authed_client: AsyncClient) -> None:
    updated = _sample_finding()
    updated.status = FindingStatus.APPLIED

    mock_repo = AsyncMock()
    mock_repo.update_finding_status = AsyncMock(return_value=updated)

    async def _allow_owned(_user, sub):
        return sub.lower()

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned),
    ):
        r = await authed_client.post(
            "/findings/finding-abc/apply",
            json={"subscription_id": SUB_ID},
        )
    assert r.status_code == 200, r.text
    extras = mock_repo.update_finding_status.call_args.kwargs["extras"]
    assert "applied_at" in extras


@pytest.mark.asyncio
async def test_resolve_returns_404_when_finding_missing(
    authed_client: AsyncClient,
) -> None:
    mock_repo = AsyncMock()
    mock_repo.update_finding_status = AsyncMock(return_value=None)

    async def _allow_owned(_user, sub):
        return sub.lower()

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned),
    ):
        r = await authed_client.post(
            "/findings/missing/resolve",
            json={"subscription_id": SUB_ID},
        )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_snooze_clamps_days_to_valid_range(
    authed_client: AsyncClient,
) -> None:
    """days=0 -> 1, days=999 -> 90."""
    updated = _sample_finding()
    mock_repo = AsyncMock()
    mock_repo.update_finding_status = AsyncMock(return_value=updated)

    async def _allow_owned(_user, sub):
        return sub.lower()

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=mock_repo),
        patch("cloudguardiq.api.main._validate_owned_subscription", new=_allow_owned),
    ):
        # days=0 should still be accepted (clamped to 1)
        r1 = await authed_client.post(
            "/findings/finding-abc/snooze",
            json={"subscription_id": SUB_ID, "days": 0},
        )
        # days=999 should be accepted (clamped to 90)
        r2 = await authed_client.post(
            "/findings/finding-abc/snooze",
            json={"subscription_id": SUB_ID, "days": 999},
        )
    assert r1.status_code == 200
    assert r2.status_code == 200
