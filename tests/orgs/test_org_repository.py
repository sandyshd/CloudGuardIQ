"""Tests for the org_id identity store (Phase 2b)."""

from __future__ import annotations

import asyncio

from cloudguardiq.core.config import Settings
from cloudguardiq.orgs.repository import (
    OrgRecord,
    OrgRepository,
    build_subject_key,
)


def _repo() -> OrgRepository:
    return OrgRepository(Settings(), cosmos_db=None)


def test_build_subject_key_strips_and_joins() -> None:
    assert build_subject_key("  iss  ", "  sub  ") == "iss|sub"


def test_provision_mints_org_id_for_new_subject() -> None:
    repo = _repo()
    rec = asyncio.run(
        repo.provision(issuer="https://x.ciamlogin.com/t/v2.0", subject="u1"),
    )
    assert len(rec.org_id) == 32
    assert rec.subject == "u1"
    assert rec.issuer == "https://x.ciamlogin.com/t/v2.0"


def test_provision_is_idempotent_for_same_subject() -> None:
    repo = _repo()
    first = asyncio.run(repo.provision(issuer="iss", subject="u1"))
    second = asyncio.run(repo.provision(issuer="iss", subject="u1"))
    assert first.org_id == second.org_id


def test_provision_distinct_subjects_get_distinct_orgs() -> None:
    repo = _repo()
    a = asyncio.run(repo.provision(issuer="iss", subject="u1"))
    b = asyncio.run(repo.provision(issuer="iss", subject="u2"))
    assert a.org_id != b.org_id


def test_get_by_subject_key_miss_returns_none() -> None:
    repo = _repo()
    assert asyncio.run(repo.get_by_subject_key("nope|nope")) is None


def test_provision_captures_email() -> None:
    repo = _repo()
    rec = asyncio.run(
        repo.provision(issuer="iss", subject="u1", email=" a@b.com "),
    )
    assert rec.email == "a@b.com"


def test_org_record_document_round_trip() -> None:
    rec = OrgRecord(
        subject_key="iss|u1",
        org_id="abc123",
        subject="u1",
        issuer="iss",
        email="a@b.com",
    )
    restored = OrgRecord.from_document(rec.to_document())
    assert restored.subject_key == "iss|u1"
    assert restored.org_id == "abc123"
    assert restored.email == "a@b.com"
