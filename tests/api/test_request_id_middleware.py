"""Verify the request-id middleware echoes the header on every response."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cloudguardiq.api.main import app


def test_health_response_includes_request_id() -> None:
    client = TestClient(app)
    r = client.get("/health")
    # Health route is unauthenticated; we still expect the request-id
    # middleware to stamp the response.
    assert r.status_code == 200
    rid = r.headers.get("x-request-id")
    assert rid is not None
    assert len(rid) >= 8


def test_request_id_is_propagated_when_caller_supplies_it() -> None:
    client = TestClient(app)
    r = client.get("/health", headers={"X-Request-Id": "trace-abc-123"})
    assert r.status_code == 200
    assert r.headers.get("x-request-id") == "trace-abc-123"

