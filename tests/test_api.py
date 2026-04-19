"""Tests for FastAPI application."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cloudguardiq.api.main import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_ok(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestScanEndpoint:
    def test_scan_returns_response(self, client: TestClient) -> None:
        response = client.post(
            "/scan",
            json={"subscription_id": "sub-123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["subscription_id"] == "sub-123"
        assert "findings_count" in data
        assert "snapshots_count" in data

    def test_scan_invalid_body(self, client: TestClient) -> None:
        response = client.post("/scan", json={})
        assert response.status_code == 422


class TestFindingsEndpoint:
    def test_get_finding_stub(self, client: TestClient) -> None:
        response = client.get("/findings/abc-123")
        assert response.status_code == 200
        assert response.json()["finding_id"] == "abc-123"
