"""Tests for FastAPI application (sync TestClient)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cloudguardiq.api.auth import TokenPayload, verify_token
from cloudguardiq.api.main import app


async def _no_auth() -> TokenPayload:
    return TokenPayload(sub="test-user", tid="test-tenant")


app.dependency_overrides[verify_token] = _no_auth
import pytest  # noqa: E402

from cloudguardiq.api import subscriptions as _subs_module  # noqa: E402
from cloudguardiq.subscriptions.repository import (  # noqa: E402
    SubscriptionRecord as _SubRec,
)


@pytest.fixture(autouse=True)
def _link_test_sub() -> None:
    """Phase 2: pre-register the test subscription on the active repo."""
    repo = _subs_module._repository
    if repo is not None:
        import asyncio
        asyncio.run(repo.upsert(_SubRec(tenant_id="test-tenant", subscription_id="sub-123")))
    yield


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
    def test_list_findings(self) -> None:
        client = _client()
        response = client.get("/findings")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert "finding_id" in data[0]

    def test_get_finding_by_id(self) -> None:
        client = _client()
        # Get a valid finding_id from the list
        findings = client.get("/findings").json()
        finding_id = findings[0]["finding_id"]
        response = client.get(f"/findings/{finding_id}")
        assert response.status_code == 200
        assert response.json()["finding_id"] == finding_id

    def test_get_finding_not_found(self) -> None:
        client = _client()
        response = client.get("/findings/nonexistent-id")
        assert response.status_code == 404

    def test_get_finding_remediation(self) -> None:
        client = _client()
        findings = client.get("/findings").json()
        finding_id = findings[0]["finding_id"]
        response = client.get(f"/findings/{finding_id}/remediation")
        assert response.status_code == 200
        data = response.json()
        assert "card_id" in data
        assert "terraform_fix" in data
