"""Smoke test: factory dispatches GCP provider to GCPAdapter."""

from __future__ import annotations

import pytest

from cloudguardiq.adapters.factory import (
    UnsupportedProviderError,
    build_scan_adapter,
)
from cloudguardiq.core.enums import CloudProvider


def test_factory_builds_gcp_adapter() -> None:
    """build_scan_adapter(GCP, project_id=...) returns a GCPAdapter."""
    from cloudguardiq.adapters.gcp.adapter import GCPAdapter

    adapter = build_scan_adapter(
        CloudProvider.GCP,
        project_id="my-proj-123",
    )
    assert isinstance(adapter, GCPAdapter)
    assert adapter.project_id == "my-proj-123"


def test_factory_rejects_gcp_without_project_id() -> None:
    """Missing project_id raises UnsupportedProviderError."""
    with pytest.raises(UnsupportedProviderError):
        build_scan_adapter(CloudProvider.GCP)
