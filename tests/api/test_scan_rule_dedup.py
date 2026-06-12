"""Tests that the interactive scan engine evaluates each rule_id once.

Regression for the duplicate-findings bug: ``NativeScanner`` seeds its rule
list from ``RULE_REGISTRY`` and ``_build_scanner`` then re-registered legacy
rules already present in the registry, so ``_build_policy_engine`` wrapped the
same rule_id twice. The scan response reported inflated counts (e.g. 82) that
collapsed to the unique count (e.g. 48) once Cosmos upserted on the stable
finding_id, blanking/shrinking the dashboard after a refresh.
"""
from __future__ import annotations

from cloudguardiq.adapters.native_scanner import NativeScanner
from cloudguardiq.adapters.rules.azure.storage import NetworkDefaultActionRule
from cloudguardiq.api.main import _build_policy_engine
from cloudguardiq.core.enums import DataTier
from cloudguardiq.core.models import ResourceSnapshot


def _noncompliant_storage() -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id="sub-1",
        resource_group="rg-1",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="acct1",
        region="eastus",
        data_tier=DataTier.TIER1_NATIVE,
        config={"network_default_action": "Allow"},
    )


def test_engine_evaluates_each_rule_id_once() -> None:
    """A rule registered twice on the scanner must fire only once."""
    scanner = NativeScanner()
    # Deliberately duplicate a registry rule, mirroring _build_scanner.
    scanner.register(NetworkDefaultActionRule())

    engine = _build_policy_engine(scanner)
    findings = engine.evaluate([_noncompliant_storage()])

    ids = [f.finding_id for f in findings]
    assert len(ids) == len(set(ids)), "duplicate finding_id emitted by engine"

    stor005 = [f for f in findings if f.rule_id == "STOR-005"]
    assert len(stor005) == 1, "STOR-005 evaluated more than once"
