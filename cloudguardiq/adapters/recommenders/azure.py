"""CloudGuardIQ -- Azure Advisor + Reservation/Savings-Plan recommenders.

Least-privilege scopes (document for the customer onboarding role):
* ``Microsoft.Advisor/recommendations/read`` (Reader covers it).
* ``Microsoft.CostManagement/benefitRecommendations/read`` for
  reservation / savings-plan recommendations.

Advisor *Cost* recommendations are per-resource and supersede the matching
heuristic rule (rightsizing -> ``FIN-005``, idle/shutdown -> ``VM-007``).
Reservation / savings-plan recommendations are account-level commitments with
no per-resource heuristic, so they carry no ``native_rule_overlap`` and are
always kept.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from functools import partial
from typing import Any

from cloudguardiq.adapters.recommenders.base import (
    RecommenderProvider,
    _to_float,
    build_recommendation_finding,
)
from cloudguardiq.core.enums import CloudProvider, Severity
from cloudguardiq.core.models import FindingResult

_IDLE_KEYWORDS = ("shut down", "shutdown", "idle", "unused", "delete", "deallocate")
_RIGHTSIZE_KEYWORDS = ("right-size", "right size", "resize", "sku", "underutilized",
                       "under-utilized", "oversized")


def _resource_group_from_arm_id(arm_id: str) -> str:
    """Extract the resource group from an ARM id (empty when absent)."""
    parts = arm_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return ""


def _classify_overlap(text: str, impacted_field: str) -> str:
    """Map an Advisor cost recommendation to the heuristic rule it supersedes."""
    if "virtualmachines" not in impacted_field.lower():
        return ""
    lowered = text.lower()
    if any(k in lowered for k in _IDLE_KEYWORDS):
        return "VM-007"
    if any(k in lowered for k in _RIGHTSIZE_KEYWORDS):
        return "FIN-005"
    return ""


def _monthly_savings(extended: dict[str, Any]) -> float:
    """Resolve a monthly USD savings figure from Advisor extendedProperties."""
    for key in ("savingsAmount", "monthlySavingsAmount", "savings"):
        if key in extended:
            return _to_float(extended[key])
    if "annualSavingsAmount" in extended:
        return _to_float(extended["annualSavingsAmount"]) / 12.0
    return 0.0


class AzureRecommenderProvider(RecommenderProvider):
    """Azure Advisor + benefit (reservation/savings-plan) recommender."""

    def __init__(
        self,
        credential: Any | None,
        subscription_id: str,
        *,
        advisor_client: Any | None = None,
        benefit_client: Any | None = None,
        advisor_factory: Callable[[Any, str], Any] | None = None,
        benefit_factory: Callable[[Any, str], Any] | None = None,
    ) -> None:
        self._credential = credential
        self._subscription_id = subscription_id
        self._advisor_client = advisor_client
        self._benefit_client = benefit_client
        self._advisor_factory = advisor_factory
        self._benefit_factory = benefit_factory

    def _make_advisor(self) -> Any | None:
        if self._advisor_client is not None:
            return self._advisor_client
        if self._advisor_factory is not None:
            return self._advisor_factory(self._credential, self._subscription_id)
        if self._credential is None:
            return None
        from azure.mgmt.advisor import AdvisorManagementClient

        return AdvisorManagementClient(self._credential, self._subscription_id)

    def _make_benefit(self) -> Any | None:
        if self._benefit_client is not None:
            return self._benefit_client
        if self._benefit_factory is not None:
            return self._benefit_factory(self._credential, self._subscription_id)
        if self._credential is None:
            return None
        from azure.mgmt.costmanagement import CostManagementClient

        return CostManagementClient(self._credential)

    async def _fetch_recommendations(self, scope: str) -> list[FindingResult]:
        loop = asyncio.get_running_loop()
        findings: list[FindingResult] = []

        advisor = self._make_advisor()
        if advisor is not None:
            recs: list[Any] = await loop.run_in_executor(
                None, partial(list, advisor.recommendations.list())
            )
            findings.extend(self._parse_advisor(recs))

        benefit = self._make_benefit()
        if benefit is not None:
            benefit_scope = scope or (
                f"/subscriptions/{self._subscription_id}"
            )
            recs = await loop.run_in_executor(
                None,
                partial(
                    list, benefit.benefit_recommendations.list(scope=benefit_scope)
                ),
            )
            findings.extend(self._parse_benefit(recs))

        return findings

    def _parse_advisor(self, recommendations: list[Any]) -> list[FindingResult]:
        out: list[FindingResult] = []
        for rec in recommendations:
            category = str(getattr(rec, "category", "") or "")
            if category.lower() != "cost":
                continue
            extended = dict(getattr(rec, "extended_properties", None) or {})
            savings = _monthly_savings(extended)
            if savings <= 0:
                continue
            impacted_field = str(getattr(rec, "impacted_field", "") or "")
            impacted_value = str(getattr(rec, "impacted_value", "") or "")
            metadata = getattr(rec, "resource_metadata", None)
            arm_id = str(getattr(metadata, "resource_id", "") or "")
            resource_group = (
                _resource_group_from_arm_id(arm_id)
                or str(extended.get("resourceGroup", ""))
            )
            short = getattr(rec, "short_description", None)
            solution = str(getattr(short, "solution", "") or "")
            problem = str(getattr(short, "problem", "") or "")
            overlap = _classify_overlap(f"{solution} {problem}", impacted_field)
            out.append(
                build_recommendation_finding(
                    rule_id="REC-AZ-ADVISOR-COST",
                    rule_name="Azure Advisor cost recommendation",
                    provider=CloudProvider.AZURE,
                    subscription_id=self._subscription_id,
                    resource_group=resource_group,
                    resource_name=impacted_value,
                    resource_type=impacted_field or "Microsoft.Advisor/recommendations",
                    region=str(extended.get("region", "")),
                    monthly_savings=savings,
                    recommendation_id=str(getattr(rec, "id", "") or ""),
                    native_rule_overlap=overlap,
                    description=solution or problem,
                    severity=Severity.HIGH if overlap else Severity.MEDIUM,
                )
            )
        return out

    def _parse_benefit(self, recommendations: list[Any]) -> list[FindingResult]:
        out: list[FindingResult] = []
        for rec in recommendations:
            props = getattr(rec, "properties", None)
            savings = _to_float(
                getattr(props, "net_savings", None)
                or getattr(props, "annual_savings_amount", None)
            )
            if savings <= 0:
                continue
            out.append(
                build_recommendation_finding(
                    rule_id="REC-AZ-BENEFIT",
                    rule_name="Azure reservation / savings-plan recommendation",
                    provider=CloudProvider.AZURE,
                    subscription_id=self._subscription_id,
                    resource_group="",
                    resource_name=str(getattr(rec, "name", "") or "commitment"),
                    resource_type="Microsoft.CostManagement/benefitRecommendations",
                    region="",
                    monthly_savings=savings,
                    recommendation_id=str(getattr(rec, "id", "") or ""),
                    description="Purchase a reservation or savings plan to cut "
                    "on-demand spend.",
                    severity=Severity.MEDIUM,
                )
            )
        return out
