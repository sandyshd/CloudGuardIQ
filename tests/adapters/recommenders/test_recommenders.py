"""Unit tests: native recommenders normalize SDK payloads to DIRECT findings."""

from __future__ import annotations

from types import SimpleNamespace

from cloudguardiq.adapters.recommenders.aws import AwsRecommenderProvider
from cloudguardiq.adapters.recommenders.azure import AzureRecommenderProvider
from cloudguardiq.adapters.recommenders.base import NullRecommenderProvider
from cloudguardiq.adapters.recommenders.gcp import GcpRecommenderProvider
from cloudguardiq.core.enums import FindingType

# ----------------------------- Azure -----------------------------

class _FakeAdvisorRecs:
    def __init__(self, recs: list[object]) -> None:
        self._recs = recs

    def list(self) -> list[object]:
        return self._recs


class _FakeAdvisorClient:
    def __init__(self, recs: list[object]) -> None:
        self.recommendations = _FakeAdvisorRecs(recs)


class _FakeBenefitRecs:
    def __init__(self, recs: list[object]) -> None:
        self._recs = recs

    def list(self, scope: str) -> list[object]:
        return self._recs


class _FakeBenefitClient:
    def __init__(self, recs: list[object]) -> None:
        self.benefit_recommendations = _FakeBenefitRecs(recs)


def _advisor_rec(solution: str, savings: str = "42.50") -> SimpleNamespace:
    return SimpleNamespace(
        id="/advisor/recommendations/rec-1",
        category="Cost",
        impacted_field="Microsoft.Compute/virtualMachines",
        impacted_value="vm-big",
        resource_metadata=SimpleNamespace(
            resource_id=(
                "/subscriptions/s/resourceGroups/RG1/providers/"
                "Microsoft.Compute/virtualMachines/vm-big"
            )
        ),
        short_description=SimpleNamespace(problem="Underutilized", solution=solution),
        extended_properties={"savingsAmount": savings, "region": "eastus"},
    )


async def test_azure_advisor_rightsize_maps_to_fin005() -> None:
    provider = AzureRecommenderProvider(
        None,
        "sub-1",
        advisor_client=_FakeAdvisorClient([_advisor_rec("Right-size this VM")]),
    )
    findings = await provider.get_recommendations("/subscriptions/sub-1")
    assert len(findings) == 1
    f = findings[0]
    assert f.finops_method == "DIRECT"
    assert f.finops_confidence == "HIGH"
    assert f.finding_type == FindingType.FINOPS
    assert f.estimated_impact_monthly_usd == 42.5
    assert f.evidence["native_rule_overlap"] == "FIN-005"
    assert f.evidence["resource_key"] == "rg1/vm-big"
    assert f.evidence["recommendation_id"] == "/advisor/recommendations/rec-1"


async def test_azure_advisor_idle_maps_to_vm007() -> None:
    provider = AzureRecommenderProvider(
        None,
        "sub-1",
        advisor_client=_FakeAdvisorClient(
            [_advisor_rec("Shut down this idle virtual machine")]
        ),
    )
    findings = await provider.get_recommendations("/subscriptions/sub-1")
    assert findings[0].evidence["native_rule_overlap"] == "VM-007"


async def test_azure_benefit_has_no_overlap() -> None:
    rec = SimpleNamespace(
        id="/benefit/1",
        name="benefit-1",
        properties=SimpleNamespace(net_savings="100.0"),
    )
    provider = AzureRecommenderProvider(
        None,
        "sub-1",
        benefit_client=_FakeBenefitClient([rec]),
    )
    findings = await provider.get_recommendations("/subscriptions/sub-1")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "REC-AZ-BENEFIT"
    assert f.finops_method == "DIRECT"
    assert "native_rule_overlap" not in f.evidence
    assert f.estimated_impact_monthly_usd == 100.0


async def test_azure_recommender_failure_yields_empty() -> None:
    class _Boom:
        @property
        def recommendations(self) -> object:
            raise RuntimeError("advisor down")

    provider = AzureRecommenderProvider(None, "sub-1", advisor_client=_Boom())
    assert await provider.get_recommendations("/subscriptions/sub-1") == []


# ----------------------------- AWS -----------------------------

class _FakeCe:
    def get_rightsizing_recommendation(self, **kwargs: object) -> dict:
        return {
            "RightsizingRecommendations": [
                {
                    "RightsizingType": "Modify",
                    "CurrentInstance": {"ResourceId": "i-abc"},
                    "ModifyRecommendationDetail": {
                        "TargetInstances": [{"EstimatedMonthlySavings": "30.00"}]
                    },
                },
                {
                    "RightsizingType": "Terminate",
                    "CurrentInstance": {"ResourceId": "i-idle"},
                    "TerminateRecommendationDetail": {
                        "EstimatedMonthlySavings": "55.00"
                    },
                },
            ]
        }

    def get_reservation_purchase_recommendation(self, **kwargs: object) -> dict:
        return {
            "Recommendations": [
                {
                    "RecommendationId": "r-1",
                    "RecommendationDetails": {
                        "EstimatedMonthlySavingsAmount": "200.0"
                    },
                }
            ]
        }

    def get_savings_plans_purchase_recommendation(self, **kwargs: object) -> dict:
        return {
            "SavingsPlansPurchaseRecommendation": {
                "SavingsPlansPurchaseRecommendationSummary": {
                    "EstimatedMonthlySavingsAmount": "75.0"
                }
            }
        }


class _FakeComputeOptimizer:
    def get_ec2_instance_recommendations(self, **kwargs: object) -> dict:
        return {
            "instanceRecommendations": [
                {
                    "instanceArn": "arn:aws:ec2:us-east-1:1:instance/i-xyz",
                    "finding": "OVER_PROVISIONED",
                    "recommendationOptions": [
                        {"estimatedMonthlySavings": {"value": "20.0"}}
                    ],
                }
            ]
        }


async def test_aws_recommender_maps_all_sources() -> None:
    provider = AwsRecommenderProvider(
        "acct-1",
        "us-east-1",
        ce_client=_FakeCe(),
        compute_optimizer_client=_FakeComputeOptimizer(),
    )
    findings = await provider.get_recommendations("acct-1")
    by_rule = {f.rule_id: f for f in findings}

    rightsize = [f for f in findings if f.rule_id == "REC-AWS-RIGHTSIZE"]
    overlaps = {f.evidence.get("native_rule_overlap") for f in rightsize}
    assert overlaps == {"FIN-005", "VM-007"}

    assert by_rule["REC-AWS-RESERVATION"].estimated_impact_monthly_usd == 200.0
    assert "native_rule_overlap" not in by_rule["REC-AWS-RESERVATION"].evidence
    assert by_rule["REC-AWS-SAVINGS-PLAN"].estimated_impact_monthly_usd == 75.0
    co = by_rule["REC-AWS-COMPUTE-OPTIMIZER"]
    assert co.evidence["native_rule_overlap"] == "FIN-005"
    assert co.evidence["resource_key"] == "/i-xyz"
    assert all(f.finops_method == "DIRECT" for f in findings)


# ----------------------------- GCP -----------------------------

class _FakeRecommenderClient:
    def list_recommendations(self, parent: str) -> list[object]:
        if "MachineTypeRecommender" in parent:
            return [
                SimpleNamespace(
                    name=(
                        "projects/p/locations/us-central1-a/recommenders/"
                        "google.compute.instance.MachineTypeRecommender/"
                        "recommendations/inst-1"
                    ),
                    description="Resize instance",
                    primary_impact=SimpleNamespace(
                        cost_projection=SimpleNamespace(
                            cost=SimpleNamespace(units=-10, nanos=-500000000)
                        )
                    ),
                )
            ]
        return [
            SimpleNamespace(
                name="projects/p/locations/global/recommenders/cud/recommendations/c1",
                description="Buy a CUD",
                primary_impact=SimpleNamespace(
                    cost_projection=SimpleNamespace(
                        cost=SimpleNamespace(units=-100, nanos=0)
                    )
                ),
            )
        ]


async def test_gcp_recommender_maps_rightsizing_and_cud() -> None:
    provider = GcpRecommenderProvider(
        "proj-1", recommender_client=_FakeRecommenderClient()
    )
    findings = await provider.get_recommendations("proj-1")
    by_rule = {f.rule_id: f for f in findings}

    rs = by_rule["REC-GCP-RIGHTSIZE"]
    assert rs.evidence["native_rule_overlap"] == "FIN-005"
    assert rs.estimated_impact_monthly_usd == 10.5
    assert rs.evidence["resource_key"] == "/inst-1"

    cud = by_rule["REC-GCP-CUD"]
    assert "native_rule_overlap" not in cud.evidence
    assert cud.estimated_impact_monthly_usd == 100.0
    assert all(f.finops_method == "DIRECT" for f in findings)


async def test_null_recommender_returns_empty() -> None:
    assert await NullRecommenderProvider().get_recommendations("x") == []
