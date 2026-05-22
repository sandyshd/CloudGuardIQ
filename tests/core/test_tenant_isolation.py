"""Phase 1: tenant isolation regression tests.

Verifies that:
- Domain models accept and surface a ``tenant_id`` field.
- The Cosmos repository scopes reads by ``tenant_id`` so tenant B cannot
  retrieve tenant A's findings even when guessing the subscription_id.
- ``BillingRepository.tenant_id`` resolution prefers the JWT ``tid`` claim.
"""

from __future__ import annotations

import pytest

from cloudguardiq.api.auth import TokenPayload, get_tenant_id
from cloudguardiq.core.enums import CloudProvider, DataTier, Severity
from cloudguardiq.core.models import (
    FindingResult,
    RemediationCard,
    ResourceSnapshot,
)


def _snap(tenant: str, sub: str = "sub-shared") -> ResourceSnapshot:
    return ResourceSnapshot(
        tenant_id=tenant,
        subscription_id=sub,
        resource_group="rg",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="sa",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={"x": 1},
    )


def _finding(tenant: str, sub: str = "sub-shared") -> FindingResult:
    return FindingResult(
        tenant_id=tenant,
        resource_snapshot=_snap(tenant, sub),
        rule_id="STOR-001",
        severity=Severity.HIGH,
    )


# ---------------------------------------------------------------------------
# 1.1 Models carry tenant_id
# ---------------------------------------------------------------------------


def test_resource_snapshot_accepts_tenant_id() -> None:
    snap = _snap("tenant-A")
    assert snap.tenant_id == "tenant-A"


def test_resource_snapshot_defaults_tenant_id_empty() -> None:
    """Backward compat: omitting tenant_id yields empty string, not error."""
    snap = ResourceSnapshot(
        subscription_id="sub-x",
        resource_group="rg",
        resource_type="t",
        resource_name="n",
        region="r",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
    )
    assert snap.tenant_id == ""


def test_finding_result_accepts_tenant_id() -> None:
    f = _finding("tenant-A")
    assert f.tenant_id == "tenant-A"


def test_remediation_card_accepts_tenant_id() -> None:
    card = RemediationCard(tenant_id="tenant-A")
    assert card.tenant_id == "tenant-A"


# ---------------------------------------------------------------------------
# 1.2 Auth helper: get_tenant_id
# ---------------------------------------------------------------------------


def test_get_tenant_id_returns_tid() -> None:
    user = TokenPayload(sub="user-1", tid="tenant-A")
    assert get_tenant_id(user) == "tenant-A"


def test_get_tenant_id_raises_when_tid_missing() -> None:
    from fastapi import HTTPException

    user = TokenPayload(sub="user-1")  # no tid
    with pytest.raises(HTTPException) as exc:
        get_tenant_id(user)
    assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# 1.3 Repository tenant isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_findings_query_filters_by_tenant_id() -> None:
    """The findings query must include a tenant_id filter."""
    from cloudguardiq.core.database import _build_findings_query

    query, params = _build_findings_query(
        tenant_id="tenant-A", subscription_id="sub-shared", limit=10
    )
    assert "c.tenant_id = @tenant_id" in query
    names = {p["name"] for p in params}
    assert "@tenant_id" in names
    assert ("@sub_id" in names) or ("@subscription_id" in names)


@pytest.mark.asyncio
async def test_finding_lookup_filters_by_tenant_id() -> None:
    """Single-finding lookup must include tenant_id filter."""
    from cloudguardiq.core.database import _build_finding_lookup_query

    query, params = _build_finding_lookup_query(
        tenant_id="tenant-A", finding_id="finding-1"
    )
    assert "c.tenant_id = @tenant_id" in query
    assert any(p["name"] == "@tenant_id" for p in params)


# ---------------------------------------------------------------------------
# 1.4 Billing tenant_id resolution
# ---------------------------------------------------------------------------


def test_billing_tenant_id_uses_tid_not_sub() -> None:
    from cloudguardiq.api.billing import _tenant_id

    user = TokenPayload(sub="user-oid-123", tid="tenant-A")
    assert _tenant_id(user) == "tenant-A"


def test_billing_tenant_id_falls_back_when_tid_missing() -> None:
    """Anonymous / dev mode: TokenPayload with no tid still resolves."""
    from cloudguardiq.api.billing import _tenant_id

    user = TokenPayload(sub="anonymous")
    # Should not raise; returns sub or 'anonymous' as last resort.
    result = _tenant_id(user)
    assert result  # non-empty
