"""Regression tests for finding_id dedup across the rule + policy merge.

Both the interactive ``/scan`` endpoint and the scheduled ``ScanPipeline``
merge the Azure Policy compliance findings into the rule-engine output. Cosmos
upserts on ``finding_id``, so any duplicate ids in the merged list collapse to
one stored row -- making the reported scan count larger than what is actually
persisted. That is why the dashboard count (seeded from the scan response)
shrank after navigating away and back to the DB-backed list.
"""
from __future__ import annotations

from cloudguardiq.core.enums import DataTier, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot
from cloudguardiq.policy.engine import dedupe_findings_by_id


def _snap(name: str) -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id="sub-1",
        resource_group="rg-1",
        resource_type="Microsoft.Compute/virtualMachines",
        resource_name=name,
        region="eastus",
        data_tier=DataTier.TIER1_NATIVE,
    )


def _finding(rule_id: str, snap: ResourceSnapshot) -> FindingResult:
    return FindingResult(
        rule_id=rule_id,
        severity=Severity.HIGH,
        resource_snapshot=snap,
        tenant_id="tenant-x",
    )


def test_dedupe_collapses_duplicate_finding_ids() -> None:
    snap = _snap("vm-1")
    a = _finding("AZPOL-CIS-1", snap)
    b = _finding("AZPOL-CIS-1", snap)  # same rule + resource -> same id
    assert a.finding_id == b.finding_id

    out = dedupe_findings_by_id([a, b])

    assert len(out) == 1
    assert out[0] is a  # first occurrence wins


def test_dedupe_preserves_distinct_findings_and_order() -> None:
    snap = _snap("vm-1")
    a = _finding("RULE-A", snap)
    b = _finding("RULE-B", snap)
    c = _finding("RULE-A", snap)  # duplicate of a

    out = dedupe_findings_by_id([a, b, c])

    assert [f.finding_id for f in out] == [a.finding_id, b.finding_id]


def test_merged_count_matches_distinct_after_policy_merge() -> None:
    """Simulate the scan merge: rule findings + duplicate policy findings."""
    snap = _snap("vm-1")
    rule_findings = [_finding("STOR-005", snap)]
    policy_findings = [
        _finding("AZPOL-CIS-1", snap),
        _finding("AZPOL-CIS-1", snap),  # adapter emitted a duplicate
    ]
    merged = rule_findings + policy_findings
    deduped = dedupe_findings_by_id(merged)

    distinct = {f.finding_id for f in merged}
    assert len(deduped) == len(distinct) == 2
