"""Tests for cloudguardiq.compliance.scorecard."""

from __future__ import annotations

import pytest

from cloudguardiq.compliance.scorecard import (
    FRAMEWORKS,
    compute_scorecard,
    reset_catalogue_cache,
)
from cloudguardiq.core.enums import (
    CloudProvider,
    DataTier,
    FindingStatus,
    FindingType,
    Severity,
)
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    reset_catalogue_cache()


def _snapshot() -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id="sub-1",
        resource_group="rg",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="sa1",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={},
    )


def _finding(
    *,
    rule_id: str,
    severity: Severity,
    frameworks: list[str],
    status: FindingStatus = FindingStatus.OPEN,
) -> FindingResult:
    return FindingResult(
        rule_id=rule_id,
        rule_name=rule_id,
        finding_type=FindingType.SECURITY,
        severity=severity,
        description="test",
        evidence={},
        compliance_frameworks=frameworks,
        waste_monthly_usd=0.0,
        resource_snapshot=_snapshot(),
        status=status,
    )


class TestComputeScorecard:
    def test_returns_one_row_per_framework(self) -> None:
        rows = compute_scorecard([])
        assert len(rows) == len(FRAMEWORKS)
        assert {r.framework_id for r in rows} == {fw.id for fw in FRAMEWORKS}

    def test_no_findings_means_full_score(self) -> None:
        rows = {r.framework_id: r for r in compute_scorecard([])}
        # Frameworks that have at least one mapped control in the registry
        # should score 100 when there are no open findings.
        assert rows["CIS_AZURE"].score == 100
        assert rows["CIS_AZURE"].controls_failed == 0
        assert rows["CIS_AZURE"].open_findings == 0

    def test_open_finding_drops_score(self) -> None:
        # STOR-001 is tagged with CIS_3.1, SOC2_CC6.1, NIST_SC-8.
        f = _finding(
            rule_id="STOR-001",
            severity=Severity.HIGH,
            frameworks=["CIS_3.1", "SOC2_CC6.1", "NIST_SC-8"],
        )
        rows = {r.framework_id: r for r in compute_scorecard([f])}
        cis = rows["CIS_AZURE"]
        assert cis.controls_failed == 1
        assert cis.controls_failed < cis.controls_total
        assert cis.score < 100
        assert cis.open_findings == 1
        assert cis.severity_breakdown.high == 1

    def test_resolved_finding_does_not_count(self) -> None:
        f = _finding(
            rule_id="STOR-001",
            severity=Severity.HIGH,
            frameworks=["CIS_3.1"],
            status=FindingStatus.RESOLVED,
        )
        rows = {r.framework_id: r for r in compute_scorecard([f])}
        assert rows["CIS_AZURE"].controls_failed == 0
        assert rows["CIS_AZURE"].score == 100

    def test_unknown_status_string_treated_as_open(self) -> None:
        """Legacy rows with an unrecognised status value must still count
        as OPEN -- otherwise the scorecard silently reports 100%."""
        f = _finding(
            rule_id="STOR-001",
            severity=Severity.HIGH,
            frameworks=["CIS_3.1"],
        )
        # Bypass Pydantic validation to simulate a Cosmos row from before
        # the enum existed (e.g. status persisted as lowercase).
        object.__setattr__(f, "status", "open")
        rows = {r.framework_id: r for r in compute_scorecard([f])}
        assert rows["CIS_AZURE"].controls_failed == 1
        assert rows["CIS_AZURE"].open_findings == 1

    def test_none_status_treated_as_open(self) -> None:
        f = _finding(
            rule_id="STOR-001",
            severity=Severity.HIGH,
            frameworks=["CIS_3.1"],
        )
        object.__setattr__(f, "status", None)
        rows = {r.framework_id: r for r in compute_scorecard([f])}
        assert rows["CIS_AZURE"].controls_failed == 1
    def test_multiple_findings_same_control_count_once(self) -> None:
        f1 = _finding(rule_id="STOR-001", severity=Severity.HIGH, frameworks=["CIS_3.1"])
        f2 = _finding(rule_id="STOR-001", severity=Severity.HIGH, frameworks=["CIS_3.1"])
        rows = {r.framework_id: r for r in compute_scorecard([f1, f2])}
        # Same control tag -> still one failed control, but two open findings.
        assert rows["CIS_AZURE"].controls_failed == 1
        assert rows["CIS_AZURE"].open_findings == 2

    def test_pci_dss_routing(self) -> None:
        # STOR-003 is tagged with CIS_3.3 and PCI_DSS_6.5.4.
        f = _finding(
            rule_id="STOR-003",
            severity=Severity.CRITICAL,
            frameworks=["CIS_3.3", "PCI_DSS_6.5.4"],
        )
        rows = {r.framework_id: r for r in compute_scorecard([f])}
        assert rows["PCI_DSS"].controls_failed == 1
        assert rows["PCI_DSS"].severity_breakdown.critical == 1
        assert rows["CIS_AZURE"].controls_failed == 1

    def test_unknown_prefix_ignored(self) -> None:
        # FOO_1.2.3 is not routable to any framework.
        f = _finding(
            rule_id="STOR-001",
            severity=Severity.HIGH,
            frameworks=["FOO_1.2.3"],
        )
        rows = {r.framework_id: r for r in compute_scorecard([f])}
        for r in rows.values():
            assert r.controls_failed == 0

    def test_catalogue_includes_known_rules(self) -> None:
        rows = {r.framework_id: r for r in compute_scorecard([])}
        # At time of writing, CIS Azure controls discovered from the
        # registry must include the storage HTTPS-only control (CIS_3.1).
        # Asserting a non-zero count protects against accidental loss of
        # the rule introspection wiring.
        assert rows["CIS_AZURE"].controls_total > 0
        assert rows["NIST_800_53"].controls_total > 0
        assert rows["PCI_DSS"].controls_total >= 1
