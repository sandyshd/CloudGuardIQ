"""Shared fixtures for API tests."""

from __future__ import annotations

import os

import pytest

from cloudguardiq.api.main import app
from cloudguardiq.core.config import get_settings


@pytest.fixture(autouse=True)
def _api_test_isolation(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Isolate API tests from global app state and auth configuration."""
    # The dedicated auth tests need real auth behaviour to assert 401/403.
    auth_test = request.node.fspath.basename == "test_auth.py"
    if not auth_test:
        monkeypatch.setenv("CLOUDGUARDIQ_AUTH_DISABLED", "true")
        get_settings.cache_clear()

    # Other test modules (e.g. tests/test_api.py) register persistent
    # dependency_overrides on the shared ``app`` object. Clear them here so
    # API tests see the canonical ``verify_token`` behaviour.
    saved_overrides = dict(app.dependency_overrides)
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(saved_overrides)

    if not auth_test:
        get_settings.cache_clear()
        os.environ.pop("CLOUDGUARDIQ_AUTH_DISABLED", None)
