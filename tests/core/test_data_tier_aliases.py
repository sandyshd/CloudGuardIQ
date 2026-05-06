"""Tests for Phase 3 cloud-agnostic DataTier semantics.

The original Azure/Defender-specific names (TIER2_FREE_CSPM, TIER3_PAID)
remain valid wire values. New cloud-agnostic aliases (TIER2_ENRICHED,
TIER3_DEEP) must resolve to the same enum members so existing rules,
stored documents, and serialised JSON keep working unchanged.
"""

from __future__ import annotations

from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import ResourceSnapshot


def test_tier2_enriched_is_alias_of_tier2_free_cspm() -> None:
    assert DataTier.TIER2_ENRICHED is DataTier.TIER2_FREE_CSPM
    assert DataTier.TIER2_ENRICHED.value == "TIER2_FREE_CSPM"


def test_tier3_deep_is_alias_of_tier3_paid() -> None:
    assert DataTier.TIER3_DEEP is DataTier.TIER3_PAID
    assert DataTier.TIER3_DEEP.value == "TIER3_PAID"


def test_canonical_names_round_trip_through_snapshot() -> None:
    """Snapshots constructed with new aliases serialise to legacy values."""
    snap = ResourceSnapshot(
        provider=CloudProvider.AZURE,
        subscription_id="00000000-0000-0000-0000-000000000000",
        resource_group="rg",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="acct",
        region="eastus",
        data_tier=DataTier.TIER2_ENRICHED,
    )
    dumped = snap.model_dump(mode="json")
    assert dumped["data_tier"] == "TIER2_FREE_CSPM"
    # Deserialising the legacy value must yield the alias-equal member.
    restored = ResourceSnapshot(**dumped)
    assert restored.data_tier is DataTier.TIER2_ENRICHED
    assert restored.data_tier is DataTier.TIER2_FREE_CSPM


def test_aws_snapshot_uses_same_tier_enum() -> None:
    """A cloud-agnostic tier value works for non-Azure providers too."""
    snap = ResourceSnapshot(
        provider=CloudProvider.AWS,
        subscription_id="123456789012",
        resource_group="prod",
        resource_type="aws_s3_bucket",
        resource_name="logs",
        region="us-east-1",
        data_tier=DataTier.TIER3_DEEP,
    )
    assert snap.provider is CloudProvider.AWS
    assert snap.data_tier is DataTier.TIER3_PAID  # alias equality
