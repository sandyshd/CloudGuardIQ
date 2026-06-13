"""Regression: get_remediation_card must look up by finding_id.

The on-demand AI remediation endpoints call
``repo.get_remediation_card(finding_id)``. A previous implementation queried
by ``card_id`` (a UUID unrelated to the finding id), so cached cards were never
found and the API returned 404 "Finding not found" even after generation.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from cloudguardiq.core.database import CosmosRepository
from cloudguardiq.core.enums import DataTier, Severity
from cloudguardiq.core.models import (
    FindingResult,
    RemediationCard,
    ResourceSnapshot,
)


class _FakeContainer:
    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}

    async def upsert_item(self, doc: dict[str, Any]) -> None:
        self.docs[doc["id"]] = dict(doc)

    async def query_items(
        self,
        query: str,
        parameters: list[Any] | None = None,
        partition_key: str | None = None,
    ) -> Any:
        wanted = None
        for p in parameters or []:
            if p["name"] == "@finding_id":
                wanted = p["value"]
        matches = [
            d for d in self.docs.values() if d.get("finding_id") == wanted
        ]
        # Newest first, mirroring ORDER BY c.generated_at DESC.
        matches.sort(key=lambda d: d.get("generated_at", ""), reverse=True)
        for d in matches:
            yield dict(d)


class _FakeRepo:
    def __init__(self) -> None:
        self.container = _FakeContainer()

    def _remediations_container(self) -> _FakeContainer:
        return self.container


def _snap(name: str = "vm-1") -> ResourceSnapshot:
    return ResourceSnapshot(
        provider="AZURE",
        subscription_id="sub-1",
        tenant_id="tenant-x",
        resource_group="rg-1",
        resource_name=name,
        resource_type="Microsoft.Compute/virtualMachines",
        region="eastus2",
        data_tier=DataTier.TIER1_NATIVE,
    )


def _card(name: str = "vm-1") -> RemediationCard:
    finding = FindingResult(
        rule_id="VM-001",
        severity=Severity.CRITICAL,
        resource_snapshot=_snap(name),
        tenant_id="tenant-x",
    )
    return RemediationCard(
        finding_result=finding,
        tenant_id="tenant-x",
        summary="do the thing",
    )


@pytest.mark.asyncio
async def test_get_remediation_card_lookup_by_finding_id() -> None:
    repo = _FakeRepo()
    card = _card()
    finding_id = card.finding_result.finding_id

    await CosmosRepository.save_remediation_card(repo, card)  # type: ignore[arg-type]

    # Looked up by the finding_id the endpoints actually pass.
    found = await CosmosRepository.get_remediation_card(repo, finding_id)  # type: ignore[arg-type]
    assert found is not None
    assert found.card_id == card.card_id

    # The unrelated card_id must NOT resolve a card (guards the old bug).
    miss = await CosmosRepository.get_remediation_card(repo, card.card_id)  # type: ignore[arg-type]
    assert miss is None


@pytest.mark.asyncio
async def test_get_remediation_card_returns_latest() -> None:
    repo = _FakeRepo()
    older = _card()
    newer = _card()
    finding_id = older.finding_result.finding_id

    await CosmosRepository.save_remediation_card(repo, older)  # type: ignore[arg-type]
    # Make ``newer`` strictly later so ordering is deterministic.
    object.__setattr__(
        newer, "generated_at", older.generated_at + timedelta(seconds=5)
    )
    await CosmosRepository.save_remediation_card(repo, newer)  # type: ignore[arg-type]

    found = await CosmosRepository.get_remediation_card(repo, finding_id)  # type: ignore[arg-type]
    assert found is not None
    assert found.card_id == newer.card_id
