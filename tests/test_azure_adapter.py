"""Tests for AzureAdapter tiered scanning."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cloudguardiq.adapters.azure_adapter import AzureAdapter
from cloudguardiq.adapters.base import CapabilityFlags
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import ResourceSnapshot


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_snapshot(name: str = "res1") -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id="sub-123",
        resource_group="rg1",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name=name,
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={"supportsHttpsTrafficOnly": True},
    )


@pytest.fixture
def mock_db() -> MagicMock:
    db = MagicMock()
    db.get_capability_flags = AsyncMock(return_value=None)
    db.save_capability_flags = AsyncMock()
    return db


@pytest.fixture
def mock_credential() -> MagicMock:
    return MagicMock()


@pytest.fixture
def adapter(mock_credential: MagicMock, mock_db: MagicMock) -> AzureAdapter:
    return AzureAdapter(
        credential=mock_credential,
        subscription_id="sub-123",
        db=mock_db,
    )


# ---------------------------------------------------------------------------
# scan() tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_tier1_only(adapter: AzureAdapter) -> None:
    """Tier 1 only: scan returns NativeScanner results, no enrichment."""
    snapshots = [_make_snapshot("sa1"), _make_snapshot("sa2")]

    adapter._capability_detector.detect = AsyncMock(
        return_value=CapabilityFlags(
            tier1_available=True, tier2_available=False, tier3_available=False
        )
    )
    adapter._scanner.scan = AsyncMock(return_value=snapshots)

    result = await adapter.scan()

    assert len(result) == 2
    assert all(s.data_tier == DataTier.TIER1_NATIVE for s in result)
    adapter._scanner.scan.assert_awaited_once()


@pytest.mark.asyncio
async def test_scan_tier1_and_tier2(adapter: AzureAdapter) -> None:
    """Tier 2 available: verify enrichment method is called."""
    snapshots = [_make_snapshot()]

    adapter._capability_detector.detect = AsyncMock(
        return_value=CapabilityFlags(
            tier1_available=True, tier2_available=True, tier3_available=False
        )
    )
    adapter._scanner.scan = AsyncMock(return_value=snapshots)
    adapter._enrich_with_secure_score = AsyncMock(return_value=snapshots)

    result = await adapter.scan()

    assert len(result) == 1
    adapter._enrich_with_secure_score.assert_awaited_once_with(snapshots)


@pytest.mark.asyncio
async def test_scan_tier3_enrichment(adapter: AzureAdapter) -> None:
    """Tier 3 available: verify both enrichment methods are called."""
    snapshots = [_make_snapshot()]

    adapter._capability_detector.detect = AsyncMock(
        return_value=CapabilityFlags(
            tier1_available=True, tier2_available=True, tier3_available=True
        )
    )
    adapter._scanner.scan = AsyncMock(return_value=snapshots)
    adapter._enrich_with_secure_score = AsyncMock(return_value=snapshots)
    adapter._enrich_with_threat_intel = AsyncMock(return_value=snapshots)

    result = await adapter.scan()

    assert len(result) == 1
    adapter._enrich_with_secure_score.assert_awaited_once()
    adapter._enrich_with_threat_intel.assert_awaited_once()


# ---------------------------------------------------------------------------
# Graceful degradation tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tier2_failure_graceful(adapter: AzureAdapter) -> None:
    """Tier 2 enrichment raises exception -- scan still succeeds."""
    snapshots = [_make_snapshot()]

    adapter._capability_detector.detect = AsyncMock(
        return_value=CapabilityFlags(
            tier1_available=True, tier2_available=True, tier3_available=False
        )
    )
    adapter._scanner.scan = AsyncMock(return_value=snapshots)
    adapter._enrich_with_secure_score = AsyncMock(
        side_effect=RuntimeError("Defender unavailable")
    )

    result = await adapter.scan()

    assert len(result) == 1
    assert result[0].data_tier == DataTier.TIER1_NATIVE


@pytest.mark.asyncio
async def test_tier3_failure_graceful(adapter: AzureAdapter) -> None:
    """Tier 3 enrichment raises exception -- scan still succeeds."""
    snapshots = [_make_snapshot()]

    adapter._capability_detector.detect = AsyncMock(
        return_value=CapabilityFlags(
            tier1_available=True, tier2_available=False, tier3_available=True
        )
    )
    adapter._scanner.scan = AsyncMock(return_value=snapshots)
    adapter._enrich_with_threat_intel = AsyncMock(
        side_effect=RuntimeError("Threat intel unavailable")
    )

    result = await adapter.scan()

    assert len(result) == 1
    assert result[0].data_tier == DataTier.TIER1_NATIVE


# ---------------------------------------------------------------------------
# validate_connection tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_connection_true(adapter: AzureAdapter) -> None:
    """validate_connection returns True when Resource Graph responds."""
    with patch(
        "cloudguardiq.adapters.azure_adapter.ResourceGraphClient"
    ) as mock_rg_cls:
        mock_client = MagicMock()
        mock_client.resources.return_value = MagicMock(data=[{"id": "x"}])
        mock_rg_cls.return_value = mock_client

        result = await adapter.validate_connection()

    assert result is True
    mock_client.resources.assert_called_once()


@pytest.mark.asyncio
async def test_validate_connection_false(adapter: AzureAdapter) -> None:
    """validate_connection returns False when Resource Graph returns 403."""
    with patch(
        "cloudguardiq.adapters.azure_adapter.ResourceGraphClient"
    ) as mock_rg_cls:
        mock_client = MagicMock()
        mock_client.resources.side_effect = Exception("HTTP 403 Forbidden")
        mock_rg_cls.return_value = mock_client

        result = await adapter.validate_connection()

    assert result is False
