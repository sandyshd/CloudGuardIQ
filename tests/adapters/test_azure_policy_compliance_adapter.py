"""Tests for AzurePolicyComplianceAdapter.

All Azure SDK calls are mocked -- no real Azure access in CI.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from azure.core.exceptions import HttpResponseError

from cloudguardiq.adapters.azure import azure_policy_compliance_adapter as mod
from cloudguardiq.adapters.azure.azure_policy_compliance_adapter import (
    FRAMEWORK_INITIATIVES,
    AzurePolicyComplianceAdapter,
)
from cloudguardiq.core.enums import DataTier, FindingType, Severity

SUB_ID = "00000000-0000-0000-0000-000000000001"
CIS_ID = FRAMEWORK_INITIATIVES["CIS_AZURE"]
NIST_ID = FRAMEWORK_INITIATIVES["NIST_800_53"]

RESOURCE_ID = (
    f"/subscriptions/{SUB_ID}/resourceGroups/rg1/providers/"
    "Microsoft.Storage/storageAccounts/acct1"
)
POLICY_DEF_ID = (
    "/providers/Microsoft.Authorization/policyDefinitions/"
    "404c3081-a854-4457-ae30-26a93ef643f9"
)


def _state_row(
    *,
    resource_id: str = RESOURCE_ID,
    policy_definition_id: str = POLICY_DEF_ID,
    policy_definition_name: str = "DenyHttpStorage",
    timestamp: str = "2026-01-01T00:00:00Z",
) -> dict:
    """Build a representative PolicyState row (camelCase, as Azure returns)."""
    return {
        "resourceId": resource_id,
        "policyDefinitionId": policy_definition_id,
        "policyDefinitionName": policy_definition_name,
        "policyDefinitionAction": "deny",
        "policyAssignmentId": "/subscriptions/x/providers/.../assignments/cis",
        "complianceState": "NonCompliant",
        "complianceReasonCode": "HttpsRequired",
        "timestamp": timestamp,
    }


@pytest.fixture
def mock_credential() -> MagicMock:
    return MagicMock()


@pytest.fixture
def mock_db() -> AsyncMock:
    db = AsyncMock()
    db.get_policy_control_map = AsyncMock(return_value=None)
    db.save_policy_control_map = AsyncMock()
    return db


@pytest.fixture
def adapter(mock_credential: MagicMock, mock_db: AsyncMock) -> AzurePolicyComplianceAdapter:
    return AzurePolicyComplianceAdapter(
        credential=mock_credential,
        subscription_id=SUB_ID,
        db=mock_db,
        initiatives=[CIS_ID, NIST_ID],
    )


class TestFetchFindings:
    @pytest.mark.asyncio
    async def test_fetch_findings_returns_empty_when_no_initiative_assigned(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        adapter._list_assigned_initiatives = AsyncMock(return_value=set())
        result = await adapter.fetch_findings()
        assert result == []

    @pytest.mark.asyncio
    async def test_fetch_findings_returns_empty_on_403(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        adapter._list_assigned_initiatives = AsyncMock(return_value={CIS_ID})
        adapter._resolve_control_ids = AsyncMock(return_value={})

        exc = HttpResponseError("forbidden")
        exc.status_code = 403  # type: ignore[attr-defined]
        mock_client = MagicMock()
        mock_client.policy_states.list_query_results_for_subscription.side_effect = exc
        client_cls = MagicMock(return_value=mock_client)

        with patch.object(mod, "PolicyInsightsClient", client_cls):
            # Must not raise.
            result = await adapter.fetch_findings()
        assert result == []

    @pytest.mark.asyncio
    async def test_fetch_findings_skips_unassigned_initiatives(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        # Only NIST is assigned; CIS must be skipped.
        adapter._list_assigned_initiatives = AsyncMock(return_value={NIST_ID})
        adapter._resolve_control_ids = AsyncMock(return_value={})
        query_spy = AsyncMock(return_value=[])
        adapter._query_policy_states = query_spy

        await adapter.fetch_findings()

        query_spy.assert_awaited_once_with(NIST_ID)

    @pytest.mark.asyncio
    async def test_dedup_by_resource_and_policy(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        adapter._list_assigned_initiatives = AsyncMock(return_value={CIS_ID})
        adapter._resolve_control_ids = AsyncMock(return_value={})
        older = _state_row(timestamp="2026-01-01T00:00:00Z")
        newer = _state_row(timestamp="2026-02-01T00:00:00Z")
        adapter._query_policy_states = AsyncMock(return_value=[older, newer])

        # Restrict to just CIS so only one query runs.
        adapter._initiatives = [CIS_ID]
        result = await adapter.fetch_findings()

        assert len(result) == 1
        assert result[0].evidence["timestamp"] == "2026-02-01T00:00:00Z"


class TestToFinding:
    def test_to_finding_maps_all_required_fields(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        adapter._control_cache[CIS_ID] = {POLICY_DEF_ID: "3.1"}
        finding = adapter._to_finding(_state_row(), CIS_ID)

        assert finding is not None
        assert finding.rule_id == "AZPOL-DenyHttpStorage"
        assert finding.rule_name == "DenyHttpStorage"
        assert finding.severity == Severity.MEDIUM
        assert finding.finding_type == FindingType.COMPLIANCE
        assert finding.compliance_frameworks == ["CIS_AZURE:3.1"]
        assert finding.waste_monthly_usd == 0.0
        assert finding.evidence["policy_definition_id"] == POLICY_DEF_ID
        assert finding.evidence["compliance_state"] == "NonCompliant"
        assert finding.evidence["compliance_reason_code"] == "HttpsRequired"
        assert finding.resource_snapshot is not None
        assert finding.resource_snapshot.data_tier == DataTier.TIER1_NATIVE
        assert finding.resource_snapshot.config == {}
        assert finding.finding_id

    def test_to_finding_falls_back_to_framework_only_tag(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        # No control map resolved -> framework-id-only tag.
        finding = adapter._to_finding(_state_row(), CIS_ID)
        assert finding is not None
        assert finding.compliance_frameworks == ["CIS_AZURE"]

    def test_to_finding_returns_none_when_required_fields_missing(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        row = _state_row()
        del row["resourceId"]
        assert adapter._to_finding(row, CIS_ID) is None

        row2 = _state_row()
        del row2["policyDefinitionId"]
        assert adapter._to_finding(row2, CIS_ID) is None

    def test_to_finding_uses_deterministic_finding_id(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        first = adapter._to_finding(_state_row(), CIS_ID)
        second = adapter._to_finding(_state_row(), CIS_ID)
        assert first is not None and second is not None
        assert first.finding_id == second.finding_id


class TestControlIdResolution:
    @pytest.mark.asyncio
    async def test_control_id_resolution_caches_per_initiative(
        self, adapter: AzurePolicyComplianceAdapter, mock_db: AsyncMock
    ) -> None:
        # Cosmos cache hit -> the Azure SDK (PolicyClient) must not be called.
        mock_db.get_policy_control_map = AsyncMock(
            return_value={POLICY_DEF_ID: "3.1"}
        )
        policy_client_cls = MagicMock()

        with patch.object(mod, "PolicyClient", policy_client_cls):
            result = await adapter._resolve_control_ids(CIS_ID)

        assert result == {POLICY_DEF_ID: "3.1"}
        policy_client_cls.assert_not_called()


class TestQueryPolicyStates:
    @pytest.mark.asyncio
    async def test_query_policy_states_returns_empty_on_403(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        exc = HttpResponseError("forbidden")
        exc.status_code = 403  # type: ignore[attr-defined]
        mock_client = MagicMock()
        mock_client.policy_states.list_query_results_for_subscription.side_effect = exc

        with patch.object(mod, "PolicyInsightsClient", MagicMock(return_value=mock_client)):
            result = await adapter._query_policy_states(CIS_ID)
        assert result == []

    @pytest.mark.asyncio
    async def test_query_policy_states_parses_rows(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        mock_client = MagicMock()
        mock_client.policy_states.list_query_results_for_subscription.return_value = [
            _state_row()
        ]
        with patch.object(mod, "PolicyInsightsClient", MagicMock(return_value=mock_client)):
            rows = await adapter._query_policy_states(CIS_ID)
        assert len(rows) == 1
        assert rows[0]["resourceId"] == RESOURCE_ID


class TestValidateConnection:
    @pytest.mark.asyncio
    async def test_validate_connection_true(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        mock_client = MagicMock()
        mock_client.policy_assignments.list_for_subscription.return_value = [object()]
        with patch.object(mod, "PolicyClient", MagicMock(return_value=mock_client)):
            assert await adapter.validate_connection() is True

    @pytest.mark.asyncio
    async def test_validate_connection_false_on_403(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        exc = HttpResponseError("forbidden")
        exc.status_code = 403  # type: ignore[attr-defined]
        mock_client = MagicMock()
        mock_client.policy_assignments.list_for_subscription.side_effect = exc
        with patch.object(mod, "PolicyClient", MagicMock(return_value=mock_client)):
            assert await adapter.validate_connection() is False


class TestMisc:
    @pytest.mark.asyncio
    async def test_scan_returns_empty_list(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        assert await adapter.scan() == []

    @pytest.mark.asyncio
    async def test_get_api_contract_returns_field_fingerprint(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        mock_client = MagicMock()
        mock_client.policy_states.list_query_results_for_subscription.return_value = [
            _state_row()
        ]
        with patch.object(mod, "PolicyInsightsClient", MagicMock(return_value=mock_client)):
            contract = await adapter.get_api_contract()

        assert contract["provider"] == "azure"
        assert contract["endpoint"] == "policy_states"
        assert "resourceId" in contract["schema"]
        assert contract["schema"]["resourceId"] == "str"
