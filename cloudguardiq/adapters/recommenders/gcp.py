"""CloudGuardIQ -- GCP Recommender API (rightsizing + CUD) recommender.

Least-privilege scope (document for the onboarding service account):
* ``recommender.computeInstanceMachineTypeRecommendations.list``
* ``recommender.commitmentUtilizationRecommendations.list``
  (the ``roles/recommender.viewer`` predefined role covers both).

Machine-type (rightsizing) recommendations supersede the ``FIN-005``
heuristic. Committed-use-discount (CUD) recommendations are account-level and
carry no ``native_rule_overlap``.
"""

from __future__ import annotations

import asyncio
from functools import partial
from typing import Any

from cloudguardiq.adapters.recommenders.base import (
    RecommenderProvider,
    build_recommendation_finding,
)
from cloudguardiq.core.enums import CloudProvider, Severity
from cloudguardiq.core.models import FindingResult

_MACHINE_TYPE_RECOMMENDER = "google.compute.instance.MachineTypeRecommender"
_CUD_RECOMMENDER = "google.compute.commitment.UsageCommitmentRecommender"


def _money_to_monthly_savings(cost_projection: Any) -> float:
    """Convert a Recommender cost projection (negative = savings) to USD/mo.

    The Recommender API expresses projected impact as a Money value over a
    duration; a negative cost means a saving. We surface the absolute monthly
    figure.
    """
    cost = getattr(cost_projection, "cost", None)
    if cost is None:
        return 0.0
    units = float(getattr(cost, "units", 0) or 0)
    nanos = float(getattr(cost, "nanos", 0) or 0) / 1e9
    total = units + nanos
    # Negative total == projected saving.
    return abs(total) if total < 0 else 0.0


def _instance_from_name(name: str) -> str:
    """Derive a resource name from a recommendation resource name/path."""
    return name.rsplit("/", 1)[-1] if name else ""


class GcpRecommenderProvider(RecommenderProvider):
    """GCP Recommender API provider (compute rightsizing + CUD)."""

    def __init__(
        self,
        project_id: str,
        *,
        location: str = "global",
        zone: str = "us-central1-a",
        recommender_client: Any | None = None,
    ) -> None:
        self._project_id = project_id
        self._location = location
        self._zone = zone
        self._client = recommender_client

    def _make_client(self) -> Any:
        if self._client is not None:
            return self._client
        from google.cloud import recommender_v1

        return recommender_v1.RecommenderClient()

    async def _fetch_recommendations(self, scope: str) -> list[FindingResult]:
        client = self._make_client()
        loop = asyncio.get_running_loop()
        findings: list[FindingResult] = []

        rightsizing_parent = (
            f"projects/{self._project_id}/locations/{self._zone}/"
            f"recommenders/{_MACHINE_TYPE_RECOMMENDER}"
        )
        recs: list[Any] = await loop.run_in_executor(
            None,
            partial(list, client.list_recommendations(parent=rightsizing_parent)),
        )
        findings.extend(self._parse(recs, native_rule_overlap="FIN-005",
                                    rule_id="REC-GCP-RIGHTSIZE",
                                    rule_name="GCP machine-type recommendation",
                                    severity=Severity.HIGH))

        cud_parent = (
            f"projects/{self._project_id}/locations/{self._location}/"
            f"recommenders/{_CUD_RECOMMENDER}"
        )
        recs = await loop.run_in_executor(
            None,
            partial(list, client.list_recommendations(parent=cud_parent)),
        )
        findings.extend(self._parse(recs, native_rule_overlap="",
                                    rule_id="REC-GCP-CUD",
                                    rule_name="GCP committed-use-discount "
                                    "recommendation",
                                    severity=Severity.MEDIUM))
        return findings

    def _parse(
        self,
        recommendations: list[Any],
        *,
        native_rule_overlap: str,
        rule_id: str,
        rule_name: str,
        severity: Severity,
    ) -> list[FindingResult]:
        out: list[FindingResult] = []
        for rec in recommendations:
            primary = getattr(rec, "primary_impact", None)
            cost_projection = getattr(primary, "cost_projection", None)
            savings = _money_to_monthly_savings(cost_projection)
            if savings <= 0:
                continue
            name = str(getattr(rec, "name", "") or "")
            out.append(
                build_recommendation_finding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    provider=CloudProvider.GCP,
                    subscription_id=self._project_id,
                    resource_group="",
                    resource_name=_instance_from_name(name) or "commitment",
                    resource_type="compute.googleapis.com/Instance"
                    if native_rule_overlap
                    else "recommender.googleapis.com/Recommendation",
                    region=self._zone if native_rule_overlap else self._location,
                    monthly_savings=savings,
                    recommendation_id=name,
                    native_rule_overlap=native_rule_overlap,
                    description=str(getattr(rec, "description", "") or rule_name),
                    severity=severity,
                )
            )
        return out
