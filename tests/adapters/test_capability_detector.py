"""Tests for CapabilityDetector (Phase 2 — with caching and tier probing)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cloudguardiq.adapters.base import CapabilityFlags
from cloudguardiq.adapters.capability_detector import CapabilityDetector

SUB_ID = "00000000-0000-0000-0000-000000000001"


@pytest.fixture
def mock_credential() -> MagicMock:
    """Return a mock TokenCredential."""
    return MagicMock()


@pytest.fixture
def mock_db() -> AsyncMock:
    """Return a mock CosmosRepository with async methods."""
    db = AsyncMock()
    db.get_capability_flags = AsyncMock(return_value=None)
    db.save_capability_flags = AsyncMock()
    return db


@pytest.fixture
def detector(mock_credential: MagicMock, mock_db: AsyncMock) -> CapabilityDetector:
    """Return a CapabilityDetector with mocked dependencies."""
    return CapabilityDetector(
        credential=mock_credential, subscription_id=SUB_ID, db=mock_db
    )


class TestProbeTier1:
    @pytest.mark.asyncio
    async def test_tier1_always_true(self, detector: CapabilityDetector) -> None:
        """Tier 1 (Resource Graph) is always available."""
        result = await detector._probe_tier1()
        assert result is True


class TestProbeTier2:
    @pytest.mark.asyncio
    async def test_tier2_returns_true_when_defender_enabled(
        self, detector: CapabilityDetector
    ) -> None:
        """Tier 2 returns True when SecureScores.list() succeeds."""
        mock_client = AsyncMock()
        mock_client.secure_scores.list = MagicMock(
            return_value=_async_iter([{"id": "score-1"}])
        )
        mock_client.close = AsyncMock()

        with patch(
            "cloudguardiq.adapters.capability_detector.CapabilityDetector._probe_tier2",
            wraps=detector._probe_tier2,
        ), patch(
            "azure.mgmt.security.aio.SecurityCenter",
            return_value=mock_client,
        ):
            result = await detector._probe_tier2()
        assert result is True

    @pytest.mark.asyncio
    async def test_tier2_returns_false_on_403(
        self, detector: CapabilityDetector
    ) -> None:
        """Tier 2 returns False when SecureScores raises 403."""
        exc = _make_http_error(403)

        with patch(
            "azure.mgmt.security.aio.SecurityCenter",
            side_effect=exc,
        ):
            result = await detector._probe_tier2()
        assert result is False

    @pytest.mark.asyncio
    async def test_tier2_returns_false_on_exception(
        self, detector: CapabilityDetector
    ) -> None:
        """Tier 2 returns False on any unexpected exception."""
        with patch(
            "azure.mgmt.security.aio.SecurityCenter",
            side_effect=RuntimeError("network failure"),
        ):
            result = await detector._probe_tier2()
        assert result is False


class TestProbeTier3:
    @pytest.mark.asyncio
    async def test_tier3_returns_true_when_paid_defender(
        self, detector: CapabilityDetector
    ) -> None:
        """Tier 3 returns True when Alerts.list() succeeds."""
        mock_client = AsyncMock()
        mock_client.alerts.list = MagicMock(
            return_value=_async_iter([{"id": "alert-1"}])
        )
        mock_client.close = AsyncMock()

        with patch(
            "azure.mgmt.security.aio.SecurityCenter",
            return_value=mock_client,
        ):
            result = await detector._probe_tier3()
        assert result is True

    @pytest.mark.asyncio
    async def test_tier3_returns_false_on_403(
        self, detector: CapabilityDetector
    ) -> None:
        """Tier 3 returns False when Alerts raises 403."""
        exc = _make_http_error(403)

        with patch(
            "azure.mgmt.security.aio.SecurityCenter",
            side_effect=exc,
        ):
            result = await detector._probe_tier3()
        assert result is False


class TestDetectCaching:
    @pytest.mark.asyncio
    async def test_detect_uses_cache_when_fresh(
        self,
        mock_credential: MagicMock,
        mock_db: AsyncMock,
    ) -> None:
        """detect() returns cached flags without probing when cache is fresh."""
        fresh_flags = CapabilityFlags(
            tier1_available=True,
            tier2_available=True,
            tier3_available=False,
            detected_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        mock_db.get_capability_flags = AsyncMock(return_value=fresh_flags)

        det = CapabilityDetector(
            credential=mock_credential, subscription_id=SUB_ID, db=mock_db
        )

        with patch.object(det, "_probe_tier2", new_callable=AsyncMock) as p2, \
             patch.object(det, "_probe_tier3", new_callable=AsyncMock) as p3:
            result = await det.detect()

        assert result is fresh_flags
        p2.assert_not_called()
        p3.assert_not_called()
        mock_db.save_capability_flags.assert_not_called()

    @pytest.mark.asyncio
    async def test_detect_probes_when_cache_expired(
        self,
        mock_credential: MagicMock,
        mock_db: AsyncMock,
    ) -> None:
        """detect() re-probes when cached flags are older than 24 h."""
        old_flags = CapabilityFlags(
            tier1_available=True,
            tier2_available=False,
            tier3_available=False,
            detected_at=datetime.now(timezone.utc) - timedelta(hours=25),
        )
        mock_db.get_capability_flags = AsyncMock(return_value=old_flags)

        det = CapabilityDetector(
            credential=mock_credential, subscription_id=SUB_ID, db=mock_db
        )

        with patch.object(det, "_probe_tier1", new_callable=AsyncMock, return_value=True), \
             patch.object(det, "_probe_tier2", new_callable=AsyncMock, return_value=True) as p2, \
             patch.object(det, "_probe_tier3", new_callable=AsyncMock, return_value=False) as p3:
            result = await det.detect()

        assert result.tier1_available is True
        assert result.tier2_available is True
        assert result.tier3_available is False
        p2.assert_called_once()
        p3.assert_called_once()
        mock_db.save_capability_flags.assert_called_once()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _async_gen(items: list):
    for item in items:
        yield item


def _async_iter(items: list):
    return _async_gen(items)


def _make_http_error(status_code: int) -> Exception:
    """Create an exception with a status_code attribute mimicking HttpResponseError."""
    exc = Exception(f"HTTP {status_code}")
    exc.status_code = status_code  # type: ignore[attr-defined]
    return exc
