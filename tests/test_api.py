"""Tests for FastAPI application (sync TestClient)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cloudguardiq.api.main import app


def _client() -> TestClient:
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_ok(self) -> None:
        client = _client()
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "0.1.0"


class TestScanEndpoint:
    def test_scan_returns_response(self) -> None:
        client = _client()
        response = client.post(
            "/scan",
            json={"subscription_id": "sub-123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["subscription_id"] == "sub-123"
        assert "findings_count" in data
        assert "snapshots_count" in data

    def test_scan_invalid_body(self) -> None:
        client = _client()
        response = client.post("/scan", json={})
        assert response.status_code == 422


class TestFindingsEndpoint:
    def test_get_finding_stub(self) -> None:
        client = _client()
        response = client.get("/findings/abc-123")
        assert response.status_code == 200
        assert response.json()["card_id"] == "abc-123"
