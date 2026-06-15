"""Tests for the Microsoft Graph IAM enrichment adapter.

The HTTP layer (``_graph_get`` / ``_graph_post`` / ``_arm_get``) is overridden
with canned payloads so no network calls occur.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from cloudguardiq.adapters.azure.microsoft_graph_iam_adapter import (
    MicrosoftGraphIamAdapter,
)
from cloudguardiq.adapters.rules.azure.iam import (
    ClassicAdminRoleRule,
    ExternalUserPrivilegedRoleRule,
    GuestPrivilegedRoleRule,
    NoMFAConditionalAccessRule,
    SPPasswordExpiryRule,
)
from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import ResourceSnapshot

SUB = "sub-1"


def _ra(name: str, principal_id: str, role: str) -> ResourceSnapshot:
    return ResourceSnapshot(
        subscription_id=SUB,
        resource_group="unknown",
        resource_type="Microsoft.Authorization/roleAssignments",
        resource_name=name,
        region="global",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={
            "role_definition_name": role,
            "principal_type": "User",
            "principal_id": principal_id,
            "scope": f"/subscriptions/{SUB}",
            "owner_subscription_count": 1,
        },
    )


def _iso_in_days(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


class _FakeGraphAdapter(MicrosoftGraphIamAdapter):
    """Returns canned Graph/ARM payloads instead of making HTTP calls."""

    def __init__(self, **responses: Any) -> None:
        super().__init__(credential=object(), subscription_id=SUB)
        self._responses = responses

    async def _graph_get(self, path: str) -> dict[str, Any]:
        if "conditionalAccess/policies" in path:
            return self._responses.get("ca_policies", {"value": []})
        if "/servicePrincipals/" in path:
            sp_id = path.split("/servicePrincipals/")[1].split("?")[0]
            return self._responses.get("sps", {}).get(
                sp_id, {"passwordCredentials": []}
            )
        return {}

    async def _graph_post(
        self, path: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        if "getByIds" in path:
            ids = set(body.get("ids", []))
            objs = [
                o
                for o in self._responses.get("directory_objects", [])
                if o.get("id") in ids
            ]
            return {"value": objs}
        return {"value": []}

    async def _arm_get(self, path: str) -> dict[str, Any]:
        if "classicAdministrators" in path:
            return self._responses.get("classic_admins", {"value": []})
        return {}


@pytest.fixture()
def directory_objects() -> list[dict[str, Any]]:
    return [
        {
            "@odata.type": "#microsoft.graph.user",
            "id": "guest-1",
            "userType": "Guest",
            "userPrincipalName": "ext_contoso.com#EXT#@tenant.onmicrosoft.com",
        },
        {
            "@odata.type": "#microsoft.graph.user",
            "id": "user-1",
            "userType": "Member",
            "userPrincipalName": "alice@tenant.onmicrosoft.com",
        },
        {
            "@odata.type": "#microsoft.graph.servicePrincipal",
            "id": "sp-1",
            "appDisplayName": "ci-runner",
        },
    ]


async def test_guest_user_enriched_iam004_iam007_fire(
    directory_objects: list[dict[str, Any]],
) -> None:
    """A guest with Owner is detected by IAM-004 and IAM-007 after enrichment."""
    adapter = _FakeGraphAdapter(directory_objects=directory_objects)
    snap = _ra("ra-guest", "guest-1", "Owner")

    out = await adapter.enrich([snap])
    cfg = out[0].config

    assert cfg["principal_type"] == "Guest"
    assert cfg["is_external_user"] is True
    assert GuestPrivilegedRoleRule().evaluate(out[0]) is not None
    assert ExternalUserPrivilegedRoleRule().evaluate(out[0]) is not None


async def test_member_user_no_mfa_fires_iam006(
    directory_objects: list[dict[str, Any]],
) -> None:
    """A member user is flagged by IAM-006 when no CA policy enforces MFA."""
    adapter = _FakeGraphAdapter(directory_objects=directory_objects)
    snap = _ra("ra-user", "user-1", "Reader")

    out = await adapter.enrich([snap])

    assert out[0].config["mfa_enforced"] is False
    assert NoMFAConditionalAccessRule().evaluate(out[0]) is not None


async def test_member_user_with_mfa_policy_passes_iam006(
    directory_objects: list[dict[str, Any]],
) -> None:
    """When a CA policy enforces MFA for all users, IAM-006 does not fire."""
    ca = {
        "value": [
            {
                "state": "enabled",
                "conditions": {"users": {"includeUsers": ["All"]}},
                "grantControls": {"builtInControls": ["mfa"]},
            }
        ]
    }
    adapter = _FakeGraphAdapter(directory_objects=directory_objects, ca_policies=ca)
    snap = _ra("ra-user", "user-1", "Reader")

    out = await adapter.enrich([snap])

    assert out[0].config["mfa_enforced"] is True
    assert NoMFAConditionalAccessRule().evaluate(out[0]) is None


async def test_service_principal_long_lived_secret_fires_iam008(
    directory_objects: list[dict[str, Any]],
) -> None:
    """An SP with a >365 day secret is flagged by IAM-008, not IAM-006."""
    sps = {"sp-1": {"passwordCredentials": [{"endDateTime": _iso_in_days(730)}]}}
    adapter = _FakeGraphAdapter(directory_objects=directory_objects, sps=sps)
    snap = _ra("ra-sp", "sp-1", "Contributor")

    out = await adapter.enrich([snap])
    cfg = out[0].config

    assert cfg["principal_type"] == "ServicePrincipal"
    assert cfg["credential_expiry_days"] >= 365
    assert cfg["mfa_enforced"] is True
    assert SPPasswordExpiryRule().evaluate(out[0]) is not None
    assert NoMFAConditionalAccessRule().evaluate(out[0]) is None


async def test_service_principal_short_secret_passes_iam008(
    directory_objects: list[dict[str, Any]],
) -> None:
    """An SP with a <365 day secret is not flagged by IAM-008."""
    sps = {"sp-1": {"passwordCredentials": [{"endDateTime": _iso_in_days(90)}]}}
    adapter = _FakeGraphAdapter(directory_objects=directory_objects, sps=sps)
    snap = _ra("ra-sp", "sp-1", "Contributor")

    out = await adapter.enrich([snap])

    assert out[0].config["credential_expiry_days"] < 365
    assert SPPasswordExpiryRule().evaluate(out[0]) is None


async def test_classic_admin_snapshot_emitted_and_iam005_fires() -> None:
    """Classic administrators become role-assignment snapshots flagged by IAM-005."""
    classic = {
        "value": [
            {
                "name": "admin@contoso.com",
                "properties": {
                    "emailAddress": "admin@contoso.com",
                    "role": "CoAdministrator",
                },
            }
        ]
    }
    adapter = _FakeGraphAdapter(directory_objects=[], classic_admins=classic)
    existing = _ra("ra-user", "user-1", "Reader")

    out = await adapter.enrich([existing])

    classics = [s for s in out if s.config.get("is_classic_admin") is True]
    assert len(classics) == 1
    assert ClassicAdminRoleRule().evaluate(classics[0]) is not None


async def test_enrich_is_noop_without_role_assignments() -> None:
    """Snapshots without any role assignments are returned untouched."""
    adapter = _FakeGraphAdapter(directory_objects=[])
    other = ResourceSnapshot(
        subscription_id=SUB,
        resource_group="rg",
        resource_type="Microsoft.Storage/storageAccounts",
        resource_name="stg",
        region="eastus",
        provider=CloudProvider.AZURE,
        data_tier=DataTier.TIER1_NATIVE,
        config={},
    )
    out = await adapter.enrich([other])
    assert out == [other]


async def test_enrich_degrades_gracefully_on_error(
    directory_objects: list[dict[str, Any]],
) -> None:
    """A failure inside enrichment leaves snapshots un-enriched, not crashed."""

    class _Boom(_FakeGraphAdapter):
        async def _resolve_principals(
            self, principal_ids: list[str]
        ) -> dict[str, dict[str, Any]]:
            raise RuntimeError("graph down")

    adapter = _Boom(directory_objects=directory_objects)
    snap = _ra("ra-user", "user-1", "Reader")

    out = await adapter.enrich([snap])

    assert "mfa_enforced" not in out[0].config
    assert NoMFAConditionalAccessRule().evaluate(out[0]) is None
