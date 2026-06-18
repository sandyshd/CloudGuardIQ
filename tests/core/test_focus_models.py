"""Tests for the FOCUS-normalized cost record model (Phase 1 FinOps)."""

from __future__ import annotations

from datetime import datetime, timezone

from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import FocusCostRecord


def _record(**overrides: object) -> FocusCostRecord:
    base: dict[str, object] = {
        "tenant_id": "tenant-a",
        "billing_period": "2026-05",
        "charge_period_start": datetime(2026, 5, 1, tzinfo=timezone.utc),
        "charge_period_end": datetime(2026, 5, 31, tzinfo=timezone.utc),
        "provider": CloudProvider.AZURE,
        "sub_account_id": "sub-1",
        "resource_id": "/subscriptions/sub-1/rg/vm-1",
        "sku_id": "Standard_D2s_v5",
        "billed_cost": 12.5,
        "effective_cost": 10.0,
        "list_cost": 15.0,
    }
    base.update(overrides)
    return FocusCostRecord(**base)  # type: ignore[arg-type]


def test_focus_record_defaults_and_fields() -> None:
    rec = _record()
    assert rec.provider is CloudProvider.AZURE
    assert rec.billing_currency == "USD"
    assert rec.charge_category == "Usage"
    assert rec.data_tier is DataTier.TIER2_FREE_CSPM
    assert rec.tags == {}
    assert rec.commitment_discount_id == ""


def test_dedup_key_is_deterministic() -> None:
    a = _record()
    b = _record()
    assert a.dedup_key() == b.dedup_key()
    assert len(a.dedup_key()) == 64  # sha256 hex


def test_dedup_key_differs_across_tenant_resource_period_sku() -> None:
    base = _record()
    assert base.dedup_key() != _record(tenant_id="tenant-b").dedup_key()
    assert base.dedup_key() != _record(resource_id="/other").dedup_key()
    assert base.dedup_key() != _record(sku_id="other-sku").dedup_key()
    assert (
        base.dedup_key()
        != _record(
            charge_period_start=datetime(2026, 6, 1, tzinfo=timezone.utc)
        ).dedup_key()
    )


def test_dedup_key_independent_of_cost_amounts() -> None:
    """Same identity but different costs must collapse to one document."""
    a = _record(billed_cost=1.0, effective_cost=1.0, list_cost=1.0)
    b = _record(billed_cost=999.0, effective_cost=999.0, list_cost=999.0)
    assert a.dedup_key() == b.dedup_key()
