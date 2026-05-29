"""CloudGuardIQ -- AzurePolicyComplianceAdapter.

Reads compliance state directly from Microsoft's Azure Policy *Regulatory
Compliance* API instead of re-implementing every regulatory control locally.

Microsoft continuously evaluates resources against the built-in regulatory
initiatives (CIS Azure, NIST SP 800-53, ISO 27001, PCI DSS, SOC 2, HIPAA).
This adapter ingests those evaluation results, normalises each non-compliant
state into a :class:`FindingResult`, and hands them to the existing pipeline
(scorecard, PDF readiness report, GPT remediation).

Architectural notes
--------------------
* This is an **Adapter** -- it lives in ``cloudguardiq/adapters/`` and never
  touches ``cloudguardiq/policy/``. It emits ``FindingResult`` objects
  directly, bypassing the rule registry. The local 52 rules keep running
  unchanged for FinOps + always-on safety checks.
* Every Azure SDK call is wrapped in ``try/except``. A 403, 404, missing
  initiative assignment, or any transport error returns an empty result with
  a logged warning -- it never raises. The product works for customers who
  have not assigned a regulatory initiative.
* Emitted findings carry ``data_tier = DataTier.TIER1_NATIVE`` -- Azure Policy
  is free and Reader-role accessible, the same tier as Resource Graph.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from cloudguardiq.adapters.base import AdapterBase
from cloudguardiq.core.enums import (
    CloudProvider,
    DataTier,
    FindingType,
    Severity,
)
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

    from cloudguardiq.core.database import CosmosRepository

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional SDK imports.
#
# The Azure management SDKs are imported lazily at module load so that:
#   * unit tests can patch these module-level names with mocks, and
#   * a deployment missing one of these packages degrades gracefully instead
#     of failing to import the whole adapter.
# ---------------------------------------------------------------------------
# Re-exported as Any so unit tests can patch them and mypy stays quiet about
# the import-fallback reassignment to None when an SDK is absent.
PolicyInsightsClient: Any = None
QueryOptions: Any = None
PolicyClient: Any = None

try:  # pragma: no cover - import wiring
    import azure.mgmt.policyinsights as _policyinsights
    import azure.mgmt.policyinsights.models as _policyinsights_models

    PolicyInsightsClient = _policyinsights.PolicyInsightsClient
    QueryOptions = _policyinsights_models.QueryOptions
except ImportError:  # pragma: no cover - exercised only when SDK absent
    pass

try:  # pragma: no cover - import wiring
    import azure.mgmt.resource as _resource

    # PolicyClient lives at the package root in azure-mgmt-resource 23.x. Newer
    # monolith builds (25.x) split it out; getattr keeps both paths working.
    PolicyClient = getattr(_resource, "PolicyClient", None)
except ImportError:  # pragma: no cover - exercised only when SDK absent
    pass

try:  # pragma: no cover - import wiring
    from azure.core.exceptions import HttpResponseError
except ImportError:  # pragma: no cover - exercised only when SDK absent

    class HttpResponseError(Exception):  # type: ignore[no-redef]
        """Fallback used when azure-core is unavailable."""


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

#: Maps our internal framework_id (matches compliance/scorecard.py FRAMEWORKS)
#: to the built-in Azure Policy initiative (policy set) definition ID.
#: IDs are stable GUIDs published by Microsoft and live at
#: /providers/Microsoft.Authorization/policySetDefinitions/{guid}.
#:
#: IMPORTANT: Verify each GUID against the live Azure Policy built-in
#: catalogue before merge. Microsoft occasionally publishes a new initiative
#: version with a new GUID; pinning to a specific GUID is intentional
#: (reproducible scoring) but must be reviewed quarterly. Source of truth:
#: https://learn.microsoft.com/azure/governance/policy/samples/
FRAMEWORK_INITIATIVES: dict[str, str] = {
    "CIS_AZURE": "/providers/Microsoft.Authorization/policySetDefinitions/06f19060-9e68-4070-92ca-f15cc126059e",  # noqa: E501 (CIS Azure 1.4.0)
    "NIST_800_53": "/providers/Microsoft.Authorization/policySetDefinitions/179d1daa-458f-4e47-8086-2a68d0d6c38f",  # noqa: E501 (NIST SP 800-53 Rev. 5)
    "ISO_27001": "/providers/Microsoft.Authorization/policySetDefinitions/89c6cddc-1c73-4ac1-b19c-54d1a15a42f2",  # noqa: E501 (ISO 27001:2013)
    "PCI_DSS": "/providers/Microsoft.Authorization/policySetDefinitions/496eeda9-8f2f-4d5e-8dfd-204f0a92ed41",  # noqa: E501 (PCI DSS v4)
    "SOC2": "/providers/Microsoft.Authorization/policySetDefinitions/4054785f-702b-4a98-bb7f-a1a37b3a4d4d",  # noqa: E501 (SOC 2 Type 2)
    "HIPAA": "/providers/Microsoft.Authorization/policySetDefinitions/a169a624-5599-4385-a696-c8d643089fab",  # noqa: E501 (HIPAA HITRUST 9.2)
}

#: Reverse lookup: initiative definition ID (lower-case) -> framework_id.
_INITIATIVE_TO_FRAMEWORK: dict[str, str] = {
    v.lower(): k for k, v in FRAMEWORK_INITIATIVES.items()
}

#: Azure Policy does not expose severity directly. Derive it from the
#: initiative's control-group metadata where possible; otherwise fall back to
#: MEDIUM. Override map for well-known high-impact policies (keyed by rule_id).
POLICY_TO_SEVERITY: dict[str, Severity] = {
    "AZPOL-DENY_ANONYMOUS_BLOB_ACCESS": Severity.CRITICAL,
    "AZPOL-REQUIRE_HTTPS_STORAGE": Severity.HIGH,
    "AZPOL-REQUIRE_MFA_PRIVILEGED": Severity.CRITICAL,
}

#: Cache TTL (in days) for resolved policy-definition -> control-id maps.
_CONTROL_MAP_TTL_DAYS = 30

#: Cache TTL (in days) for the discovered latest-initiative-per-framework map.
_LATEST_INITIATIVES_TTL_DAYS = 7

#: Azure Policy ``metadata.category`` value for built-in regulatory initiatives.
_REGULATORY_CATEGORY = "Regulatory Compliance"

#: Per-framework substring matched (case-insensitively) against a built-in
#: initiative's ``display_name`` to identify its family. Used by
#: :meth:`AzurePolicyComplianceAdapter.discover_latest_initiatives` so the
#: latest published version is found dynamically instead of pinning a GUID.
_FRAMEWORK_FAMILY_KEYWORDS: dict[str, str] = {
    "CIS_AZURE": "cis microsoft azure foundations",
    "NIST_800_53": "nist sp 800-53",
    "ISO_27001": "iso 27001",
    "PCI_DSS": "pci dss",
    "SOC2": "soc 2",
    "HIPAA": "hipaa hitrust",
}


@dataclass(frozen=True)
class ResolvedInitiative:
    """A built-in regulatory initiative resolved to its latest published version.

    Returned by :meth:`AzurePolicyComplianceAdapter.discover_latest_initiatives`.
    """

    framework_id: str
    definition_id: str
    name: str
    display_name: str
    version: str


class AzurePolicyComplianceAdapter(AdapterBase):
    """Adapter that ingests Microsoft Azure Policy regulatory compliance state.

    Args:
        credential: Azure ``TokenCredential`` for authentication.
        subscription_id: The Azure subscription ID to query.
        db: ``CosmosRepository`` used to cache control-id maps.
        initiatives: Policy initiative definition IDs to query. When ``None``
            (the default) all :data:`FRAMEWORK_INITIATIVES` values are used.
    """

    def __init__(
        self,
        credential: TokenCredential,
        subscription_id: str,
        db: CosmosRepository | None = None,
        initiatives: list[str] | None = None,
    ) -> None:
        self._credential = credential
        self._subscription_id = subscription_id
        self._db = db
        self._initiatives: list[str] = (
            list(initiatives)
            if initiatives is not None
            else list(FRAMEWORK_INITIATIVES.values())
        )
        # Populated by fetch_findings() before _to_finding() runs so the
        # synchronous converter can look up control IDs without awaiting.
        self._control_cache: dict[str, dict[str, str]] = {}

    # ------------------------------------------------------------------
    # AdapterBase abstract methods
    # ------------------------------------------------------------------

    async def scan(self) -> list[ResourceSnapshot]:
        """Return an empty list -- this adapter does not produce snapshots.

        Required by :class:`AdapterBase`, but this adapter's real work lives in
        :meth:`fetch_findings`. The orchestrator (``AzureAdapter``) calls
        :meth:`fetch_findings` separately and merges the results, so there is
        no resource-snapshot output here.
        """
        return []

    async def get_api_contract(self) -> dict[str, Any]:
        """Return a field fingerprint of a sample PolicyState response.

        Queries one initiative with ``top=1`` and records the top-level keys
        and their types so ``ContractMonitor`` can detect upstream schema
        drift. Never raises -- returns an empty schema on any failure.
        """
        schema: dict[str, str] = {}
        if PolicyInsightsClient is None or not self._initiatives:
            return {"provider": "azure", "endpoint": "policy_states", "schema": {}}
        initiative_id = self._initiatives[0]
        try:
            client = PolicyInsightsClient(self._credential, self._subscription_id)
            options = QueryOptions(
                top=1,
                filter=f"policySetDefinitionId eq '{initiative_id}'",
            )
            pager = client.policy_states.list_query_results_for_subscription(
                policy_states_resource="latest",
                subscription_id=self._subscription_id,
                query_options=options,
            )
            for state in pager:
                row = self._state_to_dict(state)
                schema = {k: type(v).__name__ for k, v in row.items()}
                break
        except Exception:
            logger.warning("Failed to fetch Policy API contract", exc_info=True)
        return {"provider": "azure", "endpoint": "policy_states", "schema": schema}

    async def validate_connection(self) -> bool:
        """Return True when Policy assignments can be listed, else False.

        Calls ``PolicyAssignmentsOperations.list_for_subscription`` with
        ``top=1``. Returns ``False`` on a 403 or any other error.
        """
        if PolicyClient is None:
            logger.warning(
                "azure-mgmt-resource PolicyClient unavailable -- "
                "cannot validate Policy connection"
            )
            return False
        try:
            client = PolicyClient(self._credential, self._subscription_id)
            pager = client.policy_assignments.list_for_subscription(top=1)
            for _ in pager:
                break
            return True
        except Exception:
            logger.warning(
                "Policy connection validation failed for %s",
                self._subscription_id,
                exc_info=True,
            )
            return False

    # ------------------------------------------------------------------
    # Legacy AdapterBase abstract methods (not applicable here)
    # ------------------------------------------------------------------

    async def list_resources(self, subscription_id: str) -> list[ResourceSnapshot]:
        """Not applicable -- this adapter emits findings, not resources."""
        return []

    async def get_resource(self, resource_id: str) -> ResourceSnapshot | None:
        """Not applicable -- this adapter emits findings, not resources."""
        return None

    async def get_cost(self, resource_id: str) -> float:
        """Not applicable -- compliance findings carry no cost signal."""
        return 0.0

    async def enrich_with_defender(
        self, snapshots: list[ResourceSnapshot]
    ) -> list[ResourceSnapshot]:
        """Not applicable -- this adapter does not enrich snapshots."""
        return snapshots

    async def get_raw_properties(self, resource_id: str) -> dict[str, Any]:
        """Not applicable -- this adapter does not fetch raw properties."""
        return {}

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    async def fetch_findings(self) -> list[FindingResult]:
        """Ingest non-compliant Policy states and return them as findings.

        For every initiative in ``self._initiatives``:
          1. Verify the initiative is assigned to the subscription.
          2. Query PolicyStates for non-compliant evaluations.
          3. Convert each non-compliant state to one :class:`FindingResult`.
          4. Deduplicate by ``(resource_id, policy_definition_id)`` -- keep the
             most recent evaluation.

        Returns the merged list. Never raises.
        """
        assigned = await self._list_assigned_initiatives()
        if not assigned:
            logger.info(
                "No regulatory initiatives assigned to %s -- "
                "skipping Policy compliance ingestion",
                self._subscription_id,
            )
            return []

        deduped: dict[tuple[str, str], FindingResult] = {}
        for initiative_id in self._initiatives:
            if initiative_id not in assigned:
                logger.debug(
                    "Initiative %s not assigned -- skipping", initiative_id
                )
                continue

            self._control_cache[initiative_id] = await self._resolve_control_ids(
                initiative_id
            )

            rows = await self._query_policy_states(initiative_id)
            for row in rows:
                finding = self._to_finding(row, initiative_id)
                if finding is None:
                    continue
                key = (
                    self._row_value(row, "resourceId", "resource_id") or "",
                    self._row_value(row, "policyDefinitionId", "policy_definition_id")
                    or "",
                )
                existing = deduped.get(key)
                if existing is None or finding.detected_at >= existing.detected_at:
                    deduped[key] = finding

        findings = list(deduped.values())
        logger.info(
            "Policy compliance ingestion produced %d finding(s) for %s",
            len(findings),
            self._subscription_id,
        )
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _list_assigned_initiatives(self) -> set[str]:
        """Return the set of initiative definition IDs assigned to the sub.

        Calls ``PolicyAssignmentsOperations.list_for_subscription`` and keeps
        every assignment whose ``policy_definition_id`` references a policy
        *set* definition (an initiative). Used to skip initiatives the
        customer has not assigned, avoiding misleading "0% compliance" scores.
        On any error returns an empty set and logs a warning.
        """
        if PolicyClient is None:
            logger.warning(
                "azure-mgmt-resource PolicyClient unavailable -- "
                "cannot list assigned initiatives"
            )
            return set()
        try:
            client = PolicyClient(self._credential, self._subscription_id)
            assigned: set[str] = set()
            for assignment in client.policy_assignments.list_for_subscription():
                definition_id = getattr(assignment, "policy_definition_id", None)
                if definition_id and "policysetdefinitions" in definition_id.lower():
                    assigned.add(definition_id)
            return assigned
        except Exception:
            logger.warning(
                "Failed to list assigned initiatives for %s",
                self._subscription_id,
                exc_info=True,
            )
            return set()

    async def _query_policy_states(self, initiative_id: str) -> list[dict[str, Any]]:
        """Return raw non-compliant PolicyState rows for an initiative.

        Calls ``PolicyStatesOperations.list_query_results_for_subscription``
        with ``policy_states_resource = "latest"`` and a ``$filter`` of
        ``policySetDefinitionId eq '<id>' and complianceState eq 'NonCompliant'``.
        Pagination is handled by the SDK's auto-paging iterator. On any error
        logs a warning and returns ``[]``.
        """
        if PolicyInsightsClient is None:
            logger.warning(
                "azure-mgmt-policyinsights unavailable -- "
                "cannot query policy states"
            )
            return []
        try:
            client = PolicyInsightsClient(self._credential, self._subscription_id)
            options = QueryOptions(
                filter=(
                    f"policySetDefinitionId eq '{initiative_id}' "
                    "and complianceState eq 'NonCompliant'"
                ),
            )
            pager = client.policy_states.list_query_results_for_subscription(
                policy_states_resource="latest",
                subscription_id=self._subscription_id,
                query_options=options,
            )
            return [self._state_to_dict(state) for state in pager]
        except HttpResponseError as exc:
            logger.warning(
                "Policy states query failed for %s (HTTP %s): %s",
                initiative_id,
                getattr(exc, "status_code", None),
                exc,
            )
            return []
        except Exception:
            logger.warning(
                "Policy states query errored for %s",
                initiative_id,
                exc_info=True,
            )
            return []

    async def _resolve_control_ids(self, initiative_id: str) -> dict[str, str]:
        """Return a ``{policy_definition_id: control_id}`` map for an initiative.

        Reads the initiative's ``policyDefinitions[].groupNames`` (built-in
        definition metadata) to map each policy definition to its framework
        control ID (e.g. ``"3.1"`` for CIS, ``"AC-2"`` for NIST). The result
        is cached in Cosmos DB for 30 days per ``initiative_id``. On any error
        returns ``{}`` -- :meth:`_to_finding` then falls back to
        framework-id-only tagging.
        """
        cached = await self._get_cached_control_map(initiative_id)
        if cached is not None:
            return cached

        if PolicyClient is None:
            return {}

        mapping: dict[str, str] = {}
        try:
            client = PolicyClient(self._credential, self._subscription_id)
            name = initiative_id.rstrip("/").split("/")[-1]
            definition = client.policy_set_definitions.get_built_in(name)
            references = getattr(definition, "policy_definitions", None) or []
            for ref in references:
                pdid = getattr(ref, "policy_definition_id", None)
                groups = getattr(ref, "group_names", None) or []
                if pdid and groups:
                    mapping[pdid] = self._control_id_from_group(groups[0])
        except Exception:
            logger.warning(
                "Failed to resolve control IDs for %s",
                initiative_id,
                exc_info=True,
            )
            return {}

        await self._save_cached_control_map(initiative_id, mapping)
        return mapping

    def _to_finding(
        self, state_row: dict[str, Any], initiative_id: str
    ) -> FindingResult | None:
        """Convert one PolicyState row to a :class:`FindingResult`.

        Returns ``None`` when the row lacks the fields we require
        (``resourceId`` and ``policyDefinitionId``).
        """
        resource_id = self._row_value(state_row, "resourceId", "resource_id")
        policy_definition_id = self._row_value(
            state_row, "policyDefinitionId", "policy_definition_id"
        )
        if not resource_id or not policy_definition_id:
            return None

        policy_name = (
            self._row_value(
                state_row, "policyDefinitionName", "policy_definition_name"
            )
            or policy_definition_id.rstrip("/").split("/")[-1]
        )
        rule_id = f"AZPOL-{policy_name}"
        rule_name = (
            self._row_value(
                state_row, "policyDefinitionName", "policy_definition_name"
            )
            or policy_name
        )
        severity = POLICY_TO_SEVERITY.get(rule_id, Severity.MEDIUM)

        action = self._row_value(
            state_row, "policyDefinitionAction", "policy_definition_action"
        )
        reason_code = self._row_value(
            state_row, "complianceReasonCode", "compliance_reason_code"
        )
        description_parts = [
            p for p in (action, reason_code) if p
        ]
        description = (
            " -- ".join(description_parts)
            if description_parts
            else "Resource is non-compliant with an assigned Azure Policy."
        )

        assignment_id = self._row_value(
            state_row, "policyAssignmentId", "policy_assignment_id"
        )
        timestamp_raw = self._row_value(state_row, "timestamp")
        detected_at = self._parse_timestamp(timestamp_raw)

        framework_id = self._framework_id_for_initiative(initiative_id)
        control_id = self._control_cache.get(initiative_id, {}).get(
            policy_definition_id
        )
        if framework_id and control_id:
            compliance_frameworks = [f"{framework_id}:{control_id}"]
        elif framework_id:
            compliance_frameworks = [framework_id]
        else:
            compliance_frameworks = []

        snapshot = self._build_minimal_snapshot(resource_id)

        finding = FindingResult(
            finding_id=AdapterBase.build_finding_id(rule_id, resource_id),
            resource_snapshot=snapshot,
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            finding_type=FindingType.COMPLIANCE,
            description=description,
            evidence={
                "policy_definition_id": policy_definition_id,
                "policy_assignment_id": assignment_id or "",
                "compliance_state": "NonCompliant",
                "compliance_reason_code": reason_code or "",
                "timestamp": timestamp_raw or "",
            },
            compliance_frameworks=compliance_frameworks,
            waste_monthly_usd=0.0,
            detected_at=detected_at,
        )
        return finding

    # ------------------------------------------------------------------
    # Internal utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _framework_id_for_initiative(initiative_id: str) -> str | None:
        """Return the internal framework_id for an initiative definition ID."""
        return _INITIATIVE_TO_FRAMEWORK.get(initiative_id.lower())

    @staticmethod
    def _control_id_from_group(group_name: str) -> str:
        """Extract a control id from an initiative group name.

        Azure group names look like ``CIS_Azure_1.4.0_3.1`` or
        ``NIST_SP_800-53_R5_AC-2``. We return the trailing token, which is the
        control id used by our scorecard tags.
        """
        token = group_name.rsplit("_", 1)[-1]
        return token or group_name

    @staticmethod
    def _build_minimal_snapshot(resource_id: str) -> ResourceSnapshot:
        """Build a minimal TIER1_NATIVE snapshot from an ARM resource id.

        We do not have the full resource config here -- that is a separate
        Resource Graph call and is not needed for compliance scoring. ``config``
        is therefore left empty.
        """
        parts = resource_id.lower().split("/")
        subscription_id = ""
        resource_group = ""
        resource_type = "unknown"
        resource_name = resource_id.rstrip("/").split("/")[-1] or "unknown"
        try:
            sub_idx = parts.index("subscriptions")
            subscription_id = parts[sub_idx + 1]
        except (ValueError, IndexError):
            pass
        try:
            rg_idx = parts.index("resourcegroups")
            resource_group = parts[rg_idx + 1]
        except (ValueError, IndexError):
            pass
        try:
            prov_idx = parts.index("providers")
            resource_type = "/".join(parts[prov_idx + 1 : prov_idx + 3]) or "unknown"
        except (ValueError, IndexError):
            pass

        return ResourceSnapshot(
            id=resource_id,
            provider=CloudProvider.AZURE,
            subscription_id=subscription_id or "unknown",
            resource_group=resource_group or "unknown",
            resource_type=resource_type,
            resource_name=resource_name,
            region="unknown",
            config={},
            data_tier=DataTier.TIER1_NATIVE,
        )

    @staticmethod
    def _row_value(row: dict[str, Any], *keys: str) -> str | None:
        """Return the first non-empty value among *keys* in *row*."""
        for key in keys:
            value = row.get(key)
            if value:
                return str(value)
        return None

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        """Parse an ISO-8601 timestamp; fall back to now() on failure."""
        if isinstance(value, datetime):
            return value
        if isinstance(value, str) and value:
            try:
                normalised = value.replace("Z", "+00:00")
                parsed = datetime.fromisoformat(normalised)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed
            except ValueError:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _state_to_dict(state: Any) -> dict[str, Any]:
        """Normalise an SDK PolicyState (or dict) into a plain dict."""
        if isinstance(state, dict):
            return state  # already a plain mapping
        as_dict = getattr(state, "as_dict", None)
        if callable(as_dict):
            try:
                return dict(as_dict())
            except Exception:  # pragma: no cover - defensive
                pass
        return {
            k: v
            for k, v in vars(state).items()
            if not k.startswith("_")
        }

    async def discover_latest_initiatives(
        self, *, use_cache: bool = True
    ) -> dict[str, ResolvedInitiative]:
        """Resolve the latest built-in initiative per supported framework.

        Lists Microsoft's built-in policy set definitions, keeps only those in
        the *Regulatory Compliance* category, matches each to a framework via
        :data:`_FRAMEWORK_FAMILY_KEYWORDS`, and selects the highest published
        version per framework. The result is cached per subscription for
        :data:`_LATEST_INITIATIVES_TTL_DAYS` days.

        This is a **read-only** operation (Reader role is sufficient); it never
        assigns or modifies anything. On any error it returns ``{}`` and logs a
        warning, so discovery failure never breaks a scan.
        """
        if use_cache:
            cached = await self._get_cached_latest_initiatives()
            if cached is not None:
                return cached

        if PolicyClient is None:
            logger.warning(
                "azure-mgmt-resource PolicyClient unavailable -- "
                "cannot discover latest initiatives"
            )
            return {}

        try:
            client = PolicyClient(self._credential, self._subscription_id)
            definitions = list(client.policy_set_definitions.list_built_in())
        except Exception:
            logger.warning(
                "Failed to list built-in policy set definitions", exc_info=True
            )
            return {}

        best: dict[str, tuple[tuple[int, ...], ResolvedInitiative]] = {}
        for definition in definitions:
            if _initiative_category(definition) != _REGULATORY_CATEGORY:
                continue
            display = str(getattr(definition, "display_name", "") or "")
            framework_id = _match_framework(display)
            if framework_id is None:
                continue
            version = _initiative_version(definition)
            sort_key = _parse_version(version)
            name = str(getattr(definition, "name", "") or "")
            definition_id = str(getattr(definition, "id", "") or "")
            if not definition_id and name:
                definition_id = (
                    "/providers/Microsoft.Authorization/"
                    f"policySetDefinitions/{name}"
                )
            if not definition_id:
                continue
            resolved = ResolvedInitiative(
                framework_id=framework_id,
                definition_id=definition_id,
                name=name,
                display_name=display,
                version=version,
            )
            current = best.get(framework_id)
            if current is None or sort_key > current[0]:
                best[framework_id] = (sort_key, resolved)

        result = {fid: pair[1] for fid, pair in best.items()}
        logger.info(
            "Discovered latest initiatives for %d framework(s) in %s",
            len(result),
            self._subscription_id,
        )
        if result:
            await self._save_cached_latest_initiatives(result)
        return result

    async def _get_cached_latest_initiatives(
        self,
    ) -> dict[str, ResolvedInitiative] | None:
        """Return a cached latest-initiative map for the subscription, or None."""
        getter = getattr(self._db, "get_latest_initiatives", None)
        if getter is None:
            return None
        try:
            raw = await getter(self._subscription_id)
        except Exception:
            logger.debug(
                "Latest-initiative cache read failed for %s",
                self._subscription_id,
                exc_info=True,
            )
            return None
        if not isinstance(raw, dict) or not raw:
            return None
        try:
            return {
                fid: ResolvedInitiative(**entry) for fid, entry in raw.items()
            }
        except (TypeError, ValueError):
            logger.debug("Discarding malformed latest-initiative cache entry")
            return None

    async def _save_cached_latest_initiatives(
        self, resolved: dict[str, ResolvedInitiative]
    ) -> None:
        """Persist the resolved latest-initiative map (best-effort)."""
        setter = getattr(self._db, "save_latest_initiatives", None)
        if setter is None:
            return
        payload = {fid: asdict(ri) for fid, ri in resolved.items()}
        try:
            await setter(
                self._subscription_id,
                payload,
                ttl_days=_LATEST_INITIATIVES_TTL_DAYS,
            )
        except Exception:
            logger.debug(
                "Latest-initiative cache write failed for %s",
                self._subscription_id,
                exc_info=True,
            )
    async def _get_cached_control_map(
        self, initiative_id: str
    ) -> dict[str, str] | None:
        """Return a cached control map for an initiative, or None on miss."""
        getter = getattr(self._db, "get_policy_control_map", None)
        if getter is None:
            return None
        try:
            result = await getter(initiative_id)
            return dict(result) if result is not None else None
        except Exception:
            logger.debug(
                "Control-map cache read failed for %s", initiative_id, exc_info=True
            )
            return None

    async def _save_cached_control_map(
        self, initiative_id: str, mapping: dict[str, str]
    ) -> None:
        """Persist a resolved control map for an initiative (best-effort)."""
        setter = getattr(self._db, "save_policy_control_map", None)
        if setter is None:
            return
        try:
            await setter(initiative_id, mapping, ttl_days=_CONTROL_MAP_TTL_DAYS)
        except Exception:
            logger.debug(
                "Control-map cache write failed for %s",
                initiative_id,
                exc_info=True,
            )


def _metadata_value(definition: Any, key: str) -> Any:
    """Return ``metadata[key]`` whether metadata is a dict or an object."""
    metadata = getattr(definition, "metadata", None)
    if metadata is None:
        return None
    if isinstance(metadata, dict):
        return metadata.get(key)
    return getattr(metadata, key, None)


def _initiative_category(definition: Any) -> str | None:
    """Return the built-in initiative's metadata category, or None."""
    value = _metadata_value(definition, "category")
    return str(value) if value is not None else None


def _initiative_version(definition: Any) -> str:
    """Return a best-effort version string for a built-in initiative.

    Prefers ``metadata.version``; falls back to a version token parsed from the
    display name; returns ``""`` when neither is available.
    """
    version = _metadata_value(definition, "version")
    if version:
        return str(version)
    display = str(getattr(definition, "display_name", "") or "")
    match = re.search(r"\bv?(\d+(?:\.\d+)+)\b", display)
    return match.group(1) if match else ""


def _parse_version(version: str) -> tuple[int, ...]:
    """Parse a version string into a comparable integer tuple.

    Empty/unparseable versions sort lowest (empty tuple). Non-numeric segments
    are ignored.
    """
    if not version:
        return ()
    parts: list[int] = []
    for segment in re.split(r"[.\-_]", version):
        if segment.isdigit():
            parts.append(int(segment))
    return tuple(parts)


def _match_framework(display_name: str) -> str | None:
    """Return the framework_id whose family keyword matches the display name."""
    lowered = display_name.lower()
    for framework_id, keyword in _FRAMEWORK_FAMILY_KEYWORDS.items():
        if keyword in lowered:
            return framework_id
    return None
