import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from cloudguardiq.core.models import ManualScanJob
from cloudguardiq.api.main import trigger_scan
from cloudguardiq.core.models import ScanRequest


@pytest.mark.asyncio
async def test_manual_scan_job_creation():
    """Test that ManualScanJob is created with correct fields."""
    job = ManualScanJob(
        scan_id="test-scan-123",
        subscription_id="sub-456",
        tenant_id="tenant-789",
        include_cost=True,
    )
    
    assert job.scan_id == "test-scan-123"
    assert job.subscription_id == "sub-456"
    assert job.tenant_id == "tenant-789"
    assert job.include_cost is True


@pytest.mark.asyncio
async def test_manual_scan_job_serialization():
    """Test ManualScanJob can be serialized to JSON."""
    job = ManualScanJob(
        scan_id="test-id",
        subscription_id="sub-id",
        tenant_id="tenant-id",
    )
    
    json_str = job.model_dump_json()
    assert "test-id" in json_str
    assert "sub-id" in json_str
    assert "tenant-id" in json_str


@pytest.mark.asyncio
async def test_manual_scan_job_deserialization():
    """Test ManualScanJob can be deserialized from JSON."""
    json_str = """{
        "scan_id": "test-id",
        "subscription_id": "sub-id",
        "tenant_id": "tenant-id",
        "include_cost": true
    }"""
    
    job = ManualScanJob.model_validate_json(json_str)
    assert job.scan_id == "test-id"
    assert job.subscription_id == "sub-id"
    assert job.include_cost is True


@pytest.mark.asyncio
async def test_trigger_scan_creates_queued_status():
    """Test that trigger_scan persists initial queued status."""
    with patch("cloudguardiq.api.main.get_repo") as mock_repo_fn, \
         patch("cloudguardiq.api.main._validate_owned_subscription"), \
         patch("cloudguardiq.api.main._enforce_scan_frequency"), \
         patch("cloudguardiq.api.main.bind_context"), \
         patch("cloudguardiq.api.main.get_settings") as mock_settings, \
         patch("cloudguardiq.api.main.get_tenant_id") as mock_tenant_id, \
         patch("cloudguardiq.api.main.os.environ.get") as mock_env:
        
        mock_settings.return_value.auth_disabled = False
        mock_tenant_id.return_value = "test-tenant"
        mock_env.return_value = None  # No Service Bus
        
        mock_repo = AsyncMock()
        mock_repo_fn.return_value = mock_repo
        
        request = ScanRequest(subscription_id="test-sub", include_cost=True)
        user = MagicMock(oid="user-123")
        
        response = await trigger_scan(request, user)
        
        assert "scan_id" in response
        assert response["status"] == "queued"
        mock_repo.save_scan_result.assert_called_once()
        
        # Verify the saved status is "queued"
        call_args = mock_repo.save_scan_result.call_args
        saved_doc = call_args[0][0]
        assert saved_doc["status"] == "queued"
