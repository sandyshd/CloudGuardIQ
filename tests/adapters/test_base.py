"""Tests for cloudguardiq.adapters.base -- AdapterBase and CapabilityFlags."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from cloudguardiq.adapters.base import AdapterBase, CapabilityFlags
from cloudguardiq.core.enums import DataTier
from cloudguardiq.core.models import ResourceSnapshot

# ---------------------------------------------------------------------------
# MockAdapter -- implements all abstract methods
# ---------------------------------------------------------------------------


class MockAdapter(AdapterBase):
    """Concrete adapter for testing purposes."""

    async def scan(self) -> list[ResourceSnapshot]:
        """Return an empty list of snapshots."""
        return []

    async def get_api_contract(self) -> dict[str, Any]:
        """Return a test contract."""
        return {"provider": "mock", "version": "1.0"}

    async def validate_connection(self) -> bool:
        """Always returns True."""
        return True

    async def list_resources(
        self, subscription_id: str
    ) -> list[ResourceSnapshot]:
        """Return empty list."""
        return []

    async def get_resource(
        self, resource_id: str
    ) -> ResourceSnapshot | None:
        """Return None."""
        return None

    async def get_cost(self, resource_id: str) -> float:
        """Return zero cost."""
        return 0.0

    async def enrich_with_defender(
        self, snapshots: list[ResourceSnapshot]
    ) -> list[ResourceSnapshot]:
        """Return snapshots unchanged."""
        return snapshots

    async def get_raw_properties(
        self, resource_id: str
    ) -> dict[str, Any]:
        """Return empty dict."""
        return {}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def adapter() -> MockAdapter:
    """Create a MockAdapter instance."""
    return MockAdapter()


@pytest.fixture
def valid_snapshot() -> ResourceSnapshot:
    """Create a valid ResourceSnapshot for testing."""
    return ResourceSnapshot(
        subscription_id="sub-123",
        resource_group="rg-test",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="teststorage",
        region="eastus",
        data_tier=DataTier.TIER1_NATIVE,
    )


# ---------------------------------------------------------------------------
# Tests: Abstract method enforcement
# ---------------------------------------------------------------------------


class TestAbstractMethodEnforcement:
    """Verify that missing abstract methods raise TypeError."""

    def test_cannot_instantiate_adapter_base(self) -> None:
        """AdapterBase itself cannot be instantiated."""
        with pytest.raises(TypeError):
            AdapterBase()  # type: ignore[abstract]

    def test_missing_scan_raises_type_error(self) -> None:
        """A subclass that skips scan() cannot be instantiated."""

        class IncompleteScan(AdapterBase):
            async def get_api_contract(self) -> dict[str, Any]:
                return {}

            async def validate_connection(self) -> bool:
                return True

            async def list_resources(
                self, subscription_id: str
            ) -> list[ResourceSnapshot]:
                return []

            async def get_resource(
                self, resource_id: str
            ) -> ResourceSnapshot | None:
                return None

            async def get_cost(self, resource_id: str) -> float:
                return 0.0

            async def enrich_with_defender(
                self, snapshots: list[ResourceSnapshot]
            ) -> list[ResourceSnapshot]:
                return snapshots

            async def get_raw_properties(
                self, resource_id: str
            ) -> dict[str, Any]:
                return {}

        with pytest.raises(TypeError):
            IncompleteScan()  # type: ignore[abstract]

    def test_missing_validate_connection_raises_type_error(self) -> None:
        """A subclass missing validate_connection() cannot be instantiated."""

        class IncompleteValidate(AdapterBase):
            async def scan(self) -> list[ResourceSnapshot]:
                return []

            async def get_api_contract(self) -> dict[str, Any]:
                return {}

            async def list_resources(
                self, subscription_id: str
            ) -> list[ResourceSnapshot]:
                return []

            async def get_resource(
                self, resource_id: str
            ) -> ResourceSnapshot | None:
                return None

            async def get_cost(self, resource_id: str) -> float:
                return 0.0

            async def enrich_with_defender(
                self, snapshots: list[ResourceSnapshot]
            ) -> list[ResourceSnapshot]:
                return snapshots

            async def get_raw_properties(
                self, resource_id: str
            ) -> dict[str, Any]:
                return {}

        with pytest.raises(TypeError):
            IncompleteValidate()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# Tests: MockAdapter abstract method implementations
# ---------------------------------------------------------------------------


class TestMockAdapterMethods:
    """Verify MockAdapter can be instantiated and its methods work."""

    @pytest.mark.asyncio
    async def test_scan_returns_list(
        self, adapter: MockAdapter
    ) -> None:
        """scan() returns an empty list."""
        result = await adapter.scan()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_api_contract_returns_dict(
        self, adapter: MockAdapter
    ) -> None:
        """get_api_contract() returns expected dict."""
        result = await adapter.get_api_contract()
        assert result == {"provider": "mock", "version": "1.0"}

    @pytest.mark.asyncio
    async def test_validate_connection_returns_true(
        self, adapter: MockAdapter
    ) -> None:
        """validate_connection() returns True."""
        result = await adapter.validate_connection()
        assert result is True


# ---------------------------------------------------------------------------
# Tests: validate_snapshot
# ---------------------------------------------------------------------------


class TestValidateSnapshot:
    """Tests for the concrete validate_snapshot helper."""

    def test_valid_snapshot_passes(
        self,
        adapter: MockAdapter,
        valid_snapshot: ResourceSnapshot,
    ) -> None:
        """A fully populated snapshot passes validation."""
        assert adapter.validate_snapshot(valid_snapshot) is True

    def test_missing_subscription_id_fails(
        self, adapter: MockAdapter
    ) -> None:
        """Empty subscription_id fails validation."""
        snap = ResourceSnapshot(
            subscription_id="",
            resource_group="rg-test",
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="teststorage",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
        )
        assert adapter.validate_snapshot(snap) is False

    def test_missing_resource_group_fails(
        self, adapter: MockAdapter
    ) -> None:
        """Empty resource_group fails validation."""
        snap = ResourceSnapshot(
            subscription_id="sub-123",
            resource_group="",
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="teststorage",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
        )
        assert adapter.validate_snapshot(snap) is False

    def test_missing_resource_name_fails(
        self, adapter: MockAdapter
    ) -> None:
        """Empty resource_name fails validation."""
        snap = ResourceSnapshot(
            subscription_id="sub-123",
            resource_group="rg-test",
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
        )
        assert adapter.validate_snapshot(snap) is False

    def test_whitespace_only_field_fails(
        self, adapter: MockAdapter
    ) -> None:
        """A field with only whitespace fails validation."""
        snap = ResourceSnapshot(
            subscription_id="sub-123",
            resource_group="   ",
            resource_type="Microsoft.Storage/storageAccounts",
            resource_name="teststorage",
            region="eastus",
            data_tier=DataTier.TIER1_NATIVE,
        )
        assert adapter.validate_snapshot(snap) is False


# ---------------------------------------------------------------------------
# Tests: build_finding_id
# ---------------------------------------------------------------------------


class TestBuildFindingId:
    """Tests for the static build_finding_id helper."""

    def test_returns_valid_uuid(self, adapter: MockAdapter) -> None:
        """build_finding_id returns a valid UUID string."""
        import uuid

        result = adapter.build_finding_id("rule-001", "resource-abc")
        parsed = uuid.UUID(result)
        assert str(parsed) == result

    def test_deterministic(self, adapter: MockAdapter) -> None:
        """Same inputs always produce the same finding ID."""
        id1 = adapter.build_finding_id("rule-001", "resource-abc")
        id2 = adapter.build_finding_id("rule-001", "resource-abc")
        assert id1 == id2

    def test_different_inputs_differ(
        self, adapter: MockAdapter
    ) -> None:
        """Different inputs produce different finding IDs."""
        id1 = adapter.build_finding_id("rule-001", "resource-abc")
        id2 = adapter.build_finding_id("rule-002", "resource-abc")
        id3 = adapter.build_finding_id("rule-001", "resource-xyz")
        assert id1 != id2
        assert id1 != id3

    def test_callable_as_static_method(self) -> None:
        """build_finding_id can be called without an instance."""
        result = AdapterBase.build_finding_id("rule-x", "res-y")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Tests: CapabilityFlags
# ---------------------------------------------------------------------------


class TestCapabilityFlags:
    """Tests for the CapabilityFlags dataclass."""

    def test_defaults(self) -> None:
        """Default flags: tier1=True, tier2=False, tier3=False."""
        flags = CapabilityFlags()
        assert flags.tier1_available is True
        assert flags.tier2_available is False
        assert flags.tier3_available is False
        assert isinstance(flags.detected_at, datetime)

    def test_custom_values(self) -> None:
        """Custom flag values are stored correctly."""
        now = datetime.now(timezone.utc)
        flags = CapabilityFlags(
            tier1_available=True,
            tier2_available=True,
            tier3_available=True,
            detected_at=now,
        )
        assert flags.tier2_available is True
        assert flags.tier3_available is True
        assert flags.detected_at == now
