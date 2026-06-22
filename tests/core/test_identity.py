"""Tests for canonical org_id identity helpers."""

from __future__ import annotations

from cloudguardiq.core.identity import (
    ANONYMOUS_ORG_ID,
    OrgIdentity,
    derive_org_id_from_tid,
    mint_org_id,
)


def test_derive_org_id_from_tid_returns_stripped_tid() -> None:
    assert derive_org_id_from_tid("  abc-123  ") == "abc-123"


def test_derive_org_id_from_tid_empty() -> None:
    assert derive_org_id_from_tid("") == ""


def test_anonymous_org_id_constant() -> None:
    assert ANONYMOUS_ORG_ID == "anonymous"


def test_org_identity_defaults() -> None:
    ident = OrgIdentity(org_id="org-1")
    assert ident.org_id == "org-1"
    assert ident.subject == ""
    assert ident.azure_tenant_id == ""
    assert ident.object_id == ""


def test_org_identity_full() -> None:
    ident = OrgIdentity(
        org_id="t-1",
        subject="user@example.com",
        azure_tenant_id="t-1",
        object_id="oid-1",
    )
    assert ident.azure_tenant_id == "t-1"
    assert ident.object_id == "oid-1"


def test_mint_org_id_is_32_hex() -> None:
    org_id = mint_org_id()
    assert len(org_id) == 32
    int(org_id, 16)  # raises if not hex


def test_mint_org_id_is_unique() -> None:
    assert mint_org_id() != mint_org_id()
