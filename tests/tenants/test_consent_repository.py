"""Phase 3.3: tenant consent repository tests."""

from __future__ import annotations

import asyncio

from cloudguardiq.core.config import Settings
from cloudguardiq.tenants.consent_repository import (
    TenantConsent,
    TenantConsentRepository,
)


def _repo() -> TenantConsentRepository:
    return TenantConsentRepository(Settings(), cosmos_db=None)


def test_get_unknown_returns_none() -> None:
    repo = _repo()
    assert asyncio.run(repo.get("11111111-1111-1111-1111-111111111111")) is None


def test_upsert_and_get() -> None:
    repo = _repo()
    consent = TenantConsent(
        customer_tenant_id="22222222-2222-2222-2222-222222222222",
        consented_by="oid-1",
    )
    asyncio.run(repo.upsert(consent))
    got = asyncio.run(
        repo.get("22222222-2222-2222-2222-222222222222"),
    )
    assert got is not None
    assert got.consented_by == "oid-1"
    assert got.is_active


def test_has_active_consent() -> None:
    repo = _repo()
    asyncio.run(repo.upsert(TenantConsent(
        customer_tenant_id="33333333-3333-3333-3333-333333333333",
    )))
    assert asyncio.run(
        repo.has_active_consent("33333333-3333-3333-3333-333333333333"),
    ) is True
    assert asyncio.run(
        repo.has_active_consent("44444444-4444-4444-4444-444444444444"),
    ) is False


def test_revoke() -> None:
    repo = _repo()
    asyncio.run(repo.upsert(TenantConsent(
        customer_tenant_id="55555555-5555-5555-5555-555555555555",
    )))
    assert asyncio.run(
        repo.revoke("55555555-5555-5555-5555-555555555555"),
    ) is True
    assert asyncio.run(
        repo.has_active_consent("55555555-5555-5555-5555-555555555555"),
    ) is False
    # Revoking again is idempotent (no-op).
    assert asyncio.run(
        repo.revoke("55555555-5555-5555-5555-555555555555"),
    ) is False


def test_document_roundtrip() -> None:
    consent = TenantConsent(
        customer_tenant_id="66666666-6666-6666-6666-666666666666",
        consented_by="oid-7",
    )
    doc = consent.to_document()
    assert doc["id"] == "66666666-6666-6666-6666-666666666666"
    assert doc["customer_tenant_id"] == "66666666-6666-6666-6666-666666666666"
    rebuilt = TenantConsent.from_document(doc)
    assert rebuilt.customer_tenant_id == consent.customer_tenant_id
    assert rebuilt.consented_by == "oid-7"
    assert rebuilt.is_active
