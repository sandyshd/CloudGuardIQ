"""Tests for AzurePolicyComplianceAdapter.

All Azure SDK calls are mocked -- no real Azure access in CI.
"""

from __future__ import annotations

import logging
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

    @pytest.mark.asyncio
    async def test_fetch_findings_ingests_custom_assigned_initiative_by_default(
        self, mock_credential: MagicMock, mock_db: AsyncMock
    ) -> None:
        # Regression: a customer assigns a CUSTOM initiative (e.g. created by
        # the "Deploy to Azure" onboarding flow) whose definition ID is NOT one
        # of the hard-coded built-in GUIDs. With the default (initiatives=None)
        # the adapter must still ingest its non-compliant states.
        custom_id = (
            f"/subscriptions/{SUB_ID}/providers/Microsoft.Authorization/"
            "policySetDefinitions/custom-cloudguardiq-compliance"
        )
        adapter = AzurePolicyComplianceAdapter(
            credential=mock_credential,
            subscription_id=SUB_ID,
            db=mock_db,
        )
        adapter._list_assigned_initiatives = AsyncMock(return_value={custom_id})
        adapter._resolve_control_ids = AsyncMock(return_value={})
        query_spy = AsyncMock(return_value=[_state_row()])
        adapter._query_policy_states = query_spy

        result = await adapter.fetch_findings()

        query_spy.assert_awaited_once_with(custom_id)
        assert len(result) == 1
        assert result[0].rule_id.startswith("AZPOL-")


    @pytest.mark.asyncio
    async def test_fetch_findings_ingests_assigned_policy_definitions(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        adapter._list_assigned_initiatives = AsyncMock(return_value=set())
        adapter._list_assigned_policy_definitions = AsyncMock(
            return_value={POLICY_DEF_ID}
        )
        adapter._resolve_control_ids = AsyncMock(return_value={})
        query_spy = AsyncMock(return_value=[_state_row()])
        adapter._query_policy_states = query_spy

        result = await adapter.fetch_findings()

        query_spy.assert_awaited_once_with(
            POLICY_DEF_ID,
            filter_field="policyDefinitionId",
        )
        assert len(result) == 1
        assert result[0].rule_id.startswith("AZPOL-")


    @pytest.mark.asyncio
    async def test_fetch_findings_logs_fetched_azure_policy_findings(
        self, adapter: AzurePolicyComplianceAdapter, caplog: pytest.LogCaptureFixture
    ) -> None:
        adapter._list_assigned_initiatives = AsyncMock(return_value={CIS_ID})
        adapter._list_assigned_policy_definitions = AsyncMock(return_value=set())
        adapter._resolve_control_ids = AsyncMock(return_value={})
        adapter._query_policy_states = AsyncMock(return_value=[_state_row()])

        with caplog.at_level(logging.INFO):
            result = await adapter.fetch_findings()

        assert len(result) == 1
        assert "Fetched Azure Policy findings for" in caplog.text
        assert "AZPOL-DenyHttpStorage" in caplog.text


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


class TestAssignedPolicyTargets:
    @pytest.mark.asyncio
    async def test_list_assigned_policy_targets_splits_sets(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        initiative_assignment = MagicMock(
            policy_definition_id=(
                "/providers/Microsoft.Authorization/"
                "policySetDefinitions/initiative-one"
            )
        )
        definition_assignment = MagicMock(
            policy_definition_id=(
                "/providers/Microsoft.Authorization/"
                "policyDefinitions/definition-one"
            )
        )
        mock_client = MagicMock()
        mock_client.policy_assignments.list_for_subscription.return_value = [
            initiative_assignment,
            definition_assignment,
        ]

        with patch.object(mod, "PolicyClient", MagicMock(return_value=mock_client)):
            initiatives, definitions = await adapter._list_assigned_policy_targets()

        assert initiatives == {
            "/providers/Microsoft.Authorization/policySetDefinitions/initiative-one"
        }
        assert definitions == {
            "/providers/Microsoft.Authorization/policyDefinitions/definition-one"
        }


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
        called = mock_client.policy_states.list_query_results_for_subscription.call_args
        options = called.kwargs["query_options"]
        assert "policySetDefinitionId" in options.filter


    @pytest.mark.asyncio
    async def test_query_policy_states_uses_policy_definition_filter_field(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        mock_client = MagicMock()
        mock_client.policy_states.list_query_results_for_subscription.return_value = [
            _state_row()
        ]

        with patch.object(mod, "PolicyInsightsClient", MagicMock(return_value=mock_client)):
            await adapter._query_policy_states(
                POLICY_DEF_ID,
                filter_field="policyDefinitionId",
            )

        called = mock_client.policy_states.list_query_results_for_subscription.call_args
        options = called.kwargs["query_options"]
        assert "policyDefinitionId" in options.filter


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


class TestDiscoverLatestInitiatives:
    @staticmethod
    def _def(*, display_name, name, category="Regulatory Compliance", version=None):
        d = MagicMock()
        d.display_name = display_name
        d.name = name
        d.id = "/providers/Microsoft.Authorization/policySetDefinitions/" + name
        meta = {"category": category}
        if version is not None:
            meta["version"] = version
        d.metadata = meta
        return d

    @pytest.mark.asyncio
    async def test_picks_highest_version_per_framework(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        defs = [
            self._def(
                display_name="CIS Microsoft Azure Foundations Benchmark v1.4.0",
                name="cis-140",
                version="1.4.0",
            ),
            self._def(
                display_name="CIS Microsoft Azure Foundations Benchmark v2.0.0",
                name="cis-200",
                version="2.0.0",
            ),
            self._def(display_name="ISO 27001:2013", name="iso", version="3.0.0"),
            self._def(
                display_name="Unrelated thing", name="x", version="9.0.0"
            ),
            self._def(
                display_name="CIS thing but not regulatory",
                name="y",
                category="Security Center",
                version="5.0.0",
            ),
        ]
        with patch.object(mod, "PolicyClient") as policy_client:
            policy_client.return_value.policy_set_definitions.list_built_in.return_value = (  # noqa: E501
                defs
            )
            result = await adapter.discover_latest_initiatives()
        assert result["CIS_AZURE"].name == "cis-200"
        assert result["CIS_AZURE"].version == "2.0.0"
        assert result["ISO_27001"].framework_id == "ISO_27001"
        assert "Unrelated thing" not in {r.display_name for r in result.values()}
        assert "y" not in {r.name for r in result.values()}

    @pytest.mark.asyncio
    async def test_returns_empty_when_policyclient_unavailable(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        with patch.object(mod, "PolicyClient", None):
            result = await adapter.discover_latest_initiatives()
        assert result == {}

    @pytest.mark.asyncio
    async def test_returns_empty_on_list_error(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        with patch.object(mod, "PolicyClient") as policy_client:
            policy_client.return_value.policy_set_definitions.list_built_in.side_effect = (  # noqa: E501
                HttpResponseError("boom")
            )
            result = await adapter.discover_latest_initiatives()
        assert result == {}

    @pytest.mark.asyncio
    async def test_uses_cache_and_skips_listing(
        self, adapter: AzurePolicyComplianceAdapter, mock_db: AsyncMock
    ) -> None:
        cached = {
            "CIS_AZURE": {
                "framework_id": "CIS_AZURE",
                "definition_id": (
                    "/providers/Microsoft.Authorization/"
                    "policySetDefinitions/cached"
                ),
                "name": "cached",
                "display_name": "CIS cached",
                "version": "2.0.0",
            }
        }
        mock_db.get_latest_initiatives = AsyncMock(return_value=cached)
        with patch.object(mod, "PolicyClient") as policy_client:
            result = await adapter.discover_latest_initiatives()
            policy_client.assert_not_called()
        assert result["CIS_AZURE"].name == "cached"

    @pytest.mark.asyncio
    async def test_saves_discovered_map_to_cache(
        self, adapter: AzurePolicyComplianceAdapter, mock_db: AsyncMock
    ) -> None:
        mock_db.get_latest_initiatives = AsyncMock(return_value=None)
        mock_db.save_latest_initiatives = AsyncMock()
        defs = [self._def(display_name="PCI DSS v4", name="pci4", version="4.0.0")]
        with patch.object(mod, "PolicyClient") as policy_client:
            policy_client.return_value.policy_set_definitions.list_built_in.return_value = (  # noqa: E501
                defs
            )
            await adapter.discover_latest_initiatives()
        mock_db.save_latest_initiatives.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_version_from_display_name_when_metadata_missing(
        self, adapter: AzurePolicyComplianceAdapter
    ) -> None:
        defs = [
            self._def(
                display_name="HIPAA HITRUST 9.2", name="hipaa", version=None
            )
        ]
        with patch.object(mod, "PolicyClient") as policy_client:
            policy_client.return_value.policy_set_definitions.list_built_in.return_value = (  # noqa: E501
                defs
            )
            result = await adapter.discover_latest_initiatives()
        assert result["HIPAA"].version == "9.2"
