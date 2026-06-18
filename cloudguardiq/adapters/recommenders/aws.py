"""CloudGuardIQ -- AWS Cost Explorer + Compute Optimizer recommenders.

Least-privilege scopes (document for the onboarding IAM role):
* ``ce:GetRightsizingRecommendation``,
  ``ce:GetReservationPurchaseRecommendation``,
  ``ce:GetSavingsPlansPurchaseRecommendation`` (Cost Explorer).
* ``compute-optimizer:GetEC2InstanceRecommendations``.

Per-instance recommendations supersede the matching heuristic rule
(modify/right-size -> ``FIN-005``, terminate/idle -> ``VM-007``). Reservation
and Savings-Plan purchase recommendations are account-level and carry no
``native_rule_overlap``.
"""

from __future__ import annotations

import asyncio
from functools import partial
from typing import Any

from cloudguardiq.adapters.recommenders.base import (
    RecommenderProvider,
    _to_float,
    build_recommendation_finding,
)
from cloudguardiq.core.enums import CloudProvider, Severity
from cloudguardiq.core.models import FindingResult


def _instance_id(resource_id: str) -> str:
    """Extract the bare EC2 instance id from an ARN or raw id."""
    if "instance/" in resource_id:
        return resource_id.rsplit("instance/", 1)[-1]
    return resource_id


class AwsRecommenderProvider(RecommenderProvider):
    """AWS Cost Explorer + Compute Optimizer recommender."""

    def __init__(
        self,
        account_id: str,
        region: str = "us-east-1",
        *,
        ce_client: Any | None = None,
        compute_optimizer_client: Any | None = None,
    ) -> None:
        self._account_id = account_id
        self._region = region
        self._ce_client = ce_client
        self._co_client = compute_optimizer_client

    def _make_ce(self) -> Any:
        if self._ce_client is not None:
            return self._ce_client
        import boto3

        return boto3.client("ce", region_name=self._region)

    def _make_co(self) -> Any:
        if self._co_client is not None:
            return self._co_client
        import boto3

        return boto3.client("compute-optimizer", region_name=self._region)

    async def _fetch_recommendations(self, scope: str) -> list[FindingResult]:
        loop = asyncio.get_running_loop()
        findings: list[FindingResult] = []

        ce = self._make_ce()
        rightsizing = await loop.run_in_executor(
            None,
            partial(
                ce.get_rightsizing_recommendation, Service="AmazonEC2"
            ),
        )
        findings.extend(self._parse_rightsizing(rightsizing))

        reservation = await loop.run_in_executor(
            None,
            partial(
                ce.get_reservation_purchase_recommendation,
                Service="Amazon Elastic Compute Cloud - Compute",
            ),
        )
        findings.extend(self._parse_reservation(reservation))

        savings_plans = await loop.run_in_executor(
            None, ce.get_savings_plans_purchase_recommendation
        )
        findings.extend(self._parse_savings_plans(savings_plans))

        co = self._make_co()
        optimizer = await loop.run_in_executor(
            None, co.get_ec2_instance_recommendations
        )
        findings.extend(self._parse_compute_optimizer(optimizer))

        return findings

    def _parse_rightsizing(self, response: dict[str, Any]) -> list[FindingResult]:
        out: list[FindingResult] = []
        for rec in response.get("RightsizingRecommendations", []) or []:
            current = rec.get("CurrentInstance", {}) or {}
            resource_id = str(current.get("ResourceId", "") or "")
            kind = str(rec.get("RightsizingType", "") or "")
            if kind.upper() == "TERMINATE":
                detail = rec.get("TerminateRecommendationDetail", {}) or {}
                savings = _to_float(detail.get("EstimatedMonthlySavings"))
                overlap = "VM-007"
            else:
                detail = rec.get("ModifyRecommendationDetail", {}) or {}
                targets = detail.get("TargetInstances", []) or []
                savings = max(
                    (_to_float(t.get("EstimatedMonthlySavings")) for t in targets),
                    default=0.0,
                )
                overlap = "FIN-005"
            if savings <= 0:
                continue
            out.append(
                build_recommendation_finding(
                    rule_id="REC-AWS-RIGHTSIZE",
                    rule_name="AWS Cost Explorer rightsizing recommendation",
                    provider=CloudProvider.AWS,
                    subscription_id=self._account_id,
                    resource_group="",
                    resource_name=_instance_id(resource_id),
                    resource_type="AWS::EC2::Instance",
                    region=self._region,
                    monthly_savings=savings,
                    recommendation_id=resource_id,
                    native_rule_overlap=overlap,
                    description=f"Cost Explorer recommends to {kind.lower()} "
                    f"instance {_instance_id(resource_id)}.",
                    severity=Severity.HIGH,
                )
            )
        return out

    def _parse_reservation(self, response: dict[str, Any]) -> list[FindingResult]:
        out: list[FindingResult] = []
        for rec in response.get("Recommendations", []) or []:
            detail = rec.get("RecommendationDetails", {}) or {}
            savings = _to_float(detail.get("EstimatedMonthlySavingsAmount"))
            if savings <= 0:
                continue
            out.append(
                build_recommendation_finding(
                    rule_id="REC-AWS-RESERVATION",
                    rule_name="AWS reservation purchase recommendation",
                    provider=CloudProvider.AWS,
                    subscription_id=self._account_id,
                    resource_group="",
                    resource_name="reservation",
                    resource_type="AWS::CostExplorer::ReservationRecommendation",
                    region=self._region,
                    monthly_savings=savings,
                    recommendation_id=str(rec.get("RecommendationId", "") or ""),
                    description="Purchase reserved instances to cut on-demand "
                    "spend.",
                    severity=Severity.MEDIUM,
                )
            )
        return out

    def _parse_savings_plans(self, response: dict[str, Any]) -> list[FindingResult]:
        out: list[FindingResult] = []
        rec = response.get("SavingsPlansPurchaseRecommendation", {}) or {}
        summary = rec.get("SavingsPlansPurchaseRecommendationSummary", {}) or {}
        savings = _to_float(summary.get("EstimatedMonthlySavingsAmount"))
        if savings <= 0:
            details = rec.get("SavingsPlansPurchaseRecommendationDetails", []) or []
            savings = sum(
                _to_float(d.get("EstimatedMonthlySavingsAmount")) for d in details
            )
        if savings <= 0:
            return out
        out.append(
            build_recommendation_finding(
                rule_id="REC-AWS-SAVINGS-PLAN",
                rule_name="AWS Savings Plan purchase recommendation",
                provider=CloudProvider.AWS,
                subscription_id=self._account_id,
                resource_group="",
                resource_name="savings-plan",
                resource_type="AWS::CostExplorer::SavingsPlanRecommendation",
                region=self._region,
                monthly_savings=savings,
                recommendation_id="savings-plan-recommendation",
                description="Purchase a Savings Plan to cut on-demand spend.",
                severity=Severity.MEDIUM,
            )
        )
        return out

    def _parse_compute_optimizer(
        self, response: dict[str, Any]
    ) -> list[FindingResult]:
        out: list[FindingResult] = []
        for rec in response.get("instanceRecommendations", []) or []:
            finding_label = str(rec.get("finding", "") or "")
            if finding_label.upper() != "OVER_PROVISIONED":
                continue
            options = rec.get("recommendationOptions", []) or []
            savings = max(
                (
                    _to_float(
                        (o.get("estimatedMonthlySavings", {}) or {}).get("value")
                    )
                    for o in options
                ),
                default=0.0,
            )
            if savings <= 0:
                continue
            arn = str(rec.get("instanceArn", "") or "")
            out.append(
                build_recommendation_finding(
                    rule_id="REC-AWS-COMPUTE-OPTIMIZER",
                    rule_name="AWS Compute Optimizer recommendation",
                    provider=CloudProvider.AWS,
                    subscription_id=self._account_id,
                    resource_group="",
                    resource_name=_instance_id(arn),
                    resource_type="AWS::EC2::Instance",
                    region=self._region,
                    monthly_savings=savings,
                    recommendation_id=arn,
                    native_rule_overlap="FIN-005",
                    description="Compute Optimizer flags this instance as "
                    "over-provisioned.",
                    severity=Severity.HIGH,
                )
            )
        return out
