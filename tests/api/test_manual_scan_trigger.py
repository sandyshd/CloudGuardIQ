from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cloudguardiq.api.main import get_scan_status, trigger_scan
from cloudguardiq.core.models import ManualScanJob, ScanRequest


@pytest.mark.asyncio
async def test_manual_scan_job_creation_with_phase3_defaults() -> None:
    """ManualScanJob tracks lifecycle and retry metadata for worker correlation."""
    job = ManualScanJob(
        scan_id="test-scan-123",
        subscription_id="sub-456",
        tenant_id="tenant-789",
        requested_by="user-abc",
        include_cost=True,
    )

    assert job.scan_id == "test-scan-123"
    assert job.subscription_id == "sub-456"
    assert job.tenant_id == "tenant-789"
    assert job.requested_by == "user-abc"
    assert job.include_cost is True
    assert job.attempt_count == 0
    assert job.max_attempts == 3
    assert job.queued_at.tzinfo is not None


@pytest.mark.asyncio
async def test_manual_scan_job_serialization_roundtrip() -> None:
    """ManualScanJob remains safely serializable for Service Bus transport."""
    job = ManualScanJob(
        scan_id="test-id",
        subscription_id="sub-id",
        tenant_id="tenant-id",
        requested_by="user-id",
    )

    restored = ManualScanJob.model_validate_json(job.model_dump_json())
    assert restored.scan_id == "test-id"
    assert restored.subscription_id == "sub-id"
    assert restored.requested_by == "user-id"


@pytest.mark.asyncio
async def test_trigger_scan_keeps_queued_when_queue_not_configured() -> None:
    """Queue misconfiguration keeps queued status so legacy polling remains compatible."""
    with (
        patch("cloudguardiq.api.main.get_repo") as mock_repo_fn,
        patch("cloudguardiq.api.main._validate_owned_subscription"),
        patch("cloudguardiq.api.main._enforce_scan_frequency"),
        patch("cloudguardiq.api.main.bind_context"),
        patch("cloudguardiq.api.main.get_settings") as mock_settings,
        patch("cloudguardiq.api.main.get_tenant_id") as mock_tenant_id,
        patch("cloudguardiq.api.main.os.environ.get") as mock_env_get,
    ):
        mock_settings.return_value.auth_disabled = False
        mock_tenant_id.return_value = "test-tenant"

        def _env_get(key: str, default: str | None = None) -> str | None:
            if key == "MANUAL_SCAN_MAX_ATTEMPTS":
                return "3"
            if key == "SERVICE_BUS_CONNECTION__FULLYQUALIFIEDNAMESPACE":
                return None
            return default

        mock_env_get.side_effect = _env_get

        mock_repo = AsyncMock()
        mock_repo_fn.return_value = mock_repo

        request = ScanRequest(subscription_id="test-sub", include_cost=True)
        user = MagicMock(oid="user-123")

        response = await trigger_scan(request, user)

        assert "scan_id" in response
        assert response["status"] == "queued"
        assert mock_repo.save_scan_result.await_count == 1

        queued_doc = mock_repo.save_scan_result.await_args_list[0].args[0]
        assert queued_doc["status"] == "queued"
        assert queued_doc["queued_at"] is not None


@pytest.mark.asyncio
async def test_get_scan_status_marks_running_timeout() -> None:
    """Long-running jobs are normalized to timed_out for deterministic UI state."""
    started_at = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    repo = AsyncMock()
    repo.get_scan_result.return_value = {
        "id": "scan-1",
        "type": "scan_result",
        "scan_id": "scan-1",
        "subscription_id": "sub-1",
        "status": "running",
        "started_at": started_at,
        "queued_at": started_at,
        "duration_seconds": 0.0,
    }

    with (
        patch("cloudguardiq.api.main.get_repo", return_value=repo),
        patch("cloudguardiq.api.main.os.environ.get", return_value="900"),
    ):
        result = await get_scan_status("scan-1", MagicMock())

    assert result["status"] == "timed_out"
    assert result["completed_at"] is not None
    repo.save_scan_result.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_scan_status_keeps_partial_enrichment_payload() -> None:
    """Completed scans may report partial enrichment while findings are valid."""
    repo = AsyncMock()
    repo.get_scan_result.return_value = {
        "id": "scan-2",
        "type": "scan_result",
        "scan_id": "scan-2",
        "subscription_id": "sub-2",
        "status": "completed",
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": 12.34,
        "partial_enrichment": True,
        "enrichment_note": "Cost enrichment may be delayed; security findings are complete.",
    }

    with patch("cloudguardiq.api.main.get_repo", return_value=repo):
        result = await get_scan_status("scan-2", MagicMock())

    assert result["status"] == "completed"
    assert result["partial_enrichment"] is True
    assert "Cost enrichment" in result["enrichment_note"]
