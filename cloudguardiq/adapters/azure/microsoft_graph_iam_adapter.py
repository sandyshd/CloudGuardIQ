"""CloudGuardIQ -- Microsoft Graph IAM enrichment adapter.

Enriches ``Microsoft.Authorization/roleAssignments`` snapshots (produced by the
``NativeScanner`` from Resource Graph) with Azure AD identity context that is
not available through Resource Graph:

* refined ``principal_type`` (User / Guest / ServicePrincipal / Group)
* ``is_external_user`` (B2B guest detection)
* ``credential_expiry_days`` (longest-lived service-principal secret)
* ``mfa_enforced`` (tenant conditional-access baseline for human identities)
* ``is_classic_admin`` (classic administrator role assignments, via ARM)

These fields drive the IAM-004..008 policy rules. The adapter is best-effort:
any failure (missing Graph permissions, network error) is logged and the
snapshots are returned unchanged so a degraded scan never breaks the pipeline.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from cloudguardiq.core.enums import CloudProvider, DataTier
from cloudguardiq.core.models import ResourceSnapshot

logger = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_ARM_BASE = "https://management.azure.com"
_ARM_SCOPE = "https://management.azure.com/.default"
_ROLE_ASSIGNMENT_TYPE = "Microsoft.Authorization/roleAssignments"
# Sentinel day count used when a service-principal secret effectively never
# expires (Graph returns a far-future endDateTime); large enough to trip the
# IAM-008 ">365 days" threshold while remaining JSON-serialisable.
_NEVER_EXPIRES_DAYS = 100000


class MicrosoftGraphIamAdapter:
    """Enrich role-assignment snapshots with Azure AD identity context.

    Args:
        credential: An Azure ``TokenCredential`` (sync or async). Used to fetch
            bearer tokens for Microsoft Graph and ARM.
        subscription_id: The subscription whose classic administrators are read.
    """

    def __init__(self, credential: Any, subscription_id: str) -> None:
        self._credential = credential
        self._subscription_id = subscription_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def enrich(
        self, snapshots: list[ResourceSnapshot]
    ) -> list[ResourceSnapshot]:
        """Enrich role-assignment snapshots in place; never raises.

        Args:
            snapshots: The full snapshot list from the Tier 1 scan.

        Returns:
            The same list, with role-assignment snapshots enriched and any
            classic-administrator snapshots appended.
        """
        role_assignments = [
            s for s in snapshots if s.resource_type == _ROLE_ASSIGNMENT_TYPE
        ]
        if not role_assignments:
            return snapshots

        try:
            principal_ids = sorted(
                {
                    str(s.config.get("principal_id") or "")
                    for s in role_assignments
                    if s.config.get("principal_id")
                }
            )
            principals = await self._resolve_principals(principal_ids)
            mfa_baseline = await self._mfa_enforced_baseline()

            for snap in role_assignments:
                await self._apply_principal(snap, principals, mfa_baseline)

            classic = await self._build_classic_admin_snapshots()
            if classic:
                snapshots = [*snapshots, *classic]
        except Exception:  # noqa: BLE001 - best-effort enrichment
            logger.warning(
                "Microsoft Graph IAM enrichment failed for %s -- "
                "continuing with un-enriched role assignments",
                self._subscription_id,
                exc_info=True,
            )
        return snapshots

    # ------------------------------------------------------------------
    # Enrichment helpers
    # ------------------------------------------------------------------

    async def _resolve_principals(
        self, principal_ids: list[str]
    ) -> dict[str, dict[str, Any]]:
        """Resolve principal ids to directory objects via Graph getByIds.

        Args:
            principal_ids: Azure AD object ids referenced by role assignments.

        Returns:
            Mapping of object id to its directory object payload.
        """
        resolved: dict[str, dict[str, Any]] = {}
        if not principal_ids:
            return resolved

        # Graph getByIds accepts up to 1000 ids per call.
        for start in range(0, len(principal_ids), 1000):
            batch = principal_ids[start : start + 1000]
            body = {
                "ids": batch,
                "types": ["user", "servicePrincipal", "group"],
            }
            data = await self._graph_post(
                f"{_GRAPH_BASE}/directoryObjects/getByIds", body
            )
            for obj in data.get("value", []) or []:
                obj_id = str(obj.get("id") or "")
                if obj_id:
                    resolved[obj_id] = obj
        return resolved

    async def _apply_principal(
        self,
        snap: ResourceSnapshot,
        principals: dict[str, dict[str, Any]],
        mfa_baseline: bool,
    ) -> None:
        """Apply resolved identity context to a single role-assignment snapshot."""
        principal_id = str(snap.config.get("principal_id") or "")
        obj = principals.get(principal_id)
        if not obj:
            return

        odata = str(obj.get("@odata.type") or "").lower()

        if "serviceprincipal" in odata:
            snap.config["principal_type"] = "ServicePrincipal"
            # MFA is not applicable to service principals -- mark enforced so
            # IAM-006 does not flag them.
            snap.config["mfa_enforced"] = True
            expiry = await self._sp_credential_expiry_days(principal_id)
            if expiry is not None:
                snap.config["credential_expiry_days"] = expiry
        elif "user" in odata:
            user_type = str(obj.get("userType") or "").lower()
            upn = str(obj.get("userPrincipalName") or "").lower()
            is_guest = user_type == "guest"
            snap.config["principal_type"] = "Guest" if is_guest else "User"
            snap.config["is_external_user"] = is_guest or "#ext#" in upn
            snap.config["mfa_enforced"] = mfa_baseline
        elif "group" in odata:
            snap.config["principal_type"] = "Group"

    async def _sp_credential_expiry_days(self, sp_object_id: str) -> int | None:
        """Return days until the furthest-out SP password credential expires.

        Args:
            sp_object_id: The service principal's directory object id.

        Returns:
            The maximum days-to-expiry across password credentials, a large
            sentinel when a credential effectively never expires, or ``None``
            when the principal has no password credentials.
        """
        data = await self._graph_get(
            f"{_GRAPH_BASE}/servicePrincipals/{sp_object_id}"
            "?$select=id,passwordCredentials"
        )
        creds = data.get("passwordCredentials") or []
        now = datetime.now(timezone.utc)
        max_days: int | None = None
        for cred in creds:
            end = self._parse_iso(str(cred.get("endDateTime") or ""))
            if end is None:
                continue
            days = (end - now).days
            if days > 5 * 365:
                days = _NEVER_EXPIRES_DAYS
            if max_days is None or days > max_days:
                max_days = days
        return max_days

    async def _mfa_enforced_baseline(self) -> bool:
        """Return True when an enabled CA policy enforces MFA for all users."""
        data = await self._graph_get(
            f"{_GRAPH_BASE}/identity/conditionalAccess/policies"
        )
        for policy in data.get("value", []) or []:
            if str(policy.get("state") or "").lower() != "enabled":
                continue
            conditions = policy.get("conditions") or {}
            users = conditions.get("users") or {}
            include = users.get("includeUsers") or []
            grant = policy.get("grantControls") or {}
            controls = [
                str(c).lower() for c in (grant.get("builtInControls") or [])
            ]
            if "mfa" in controls and "All" in include:
                return True
        return False

    async def _build_classic_admin_snapshots(self) -> list[ResourceSnapshot]:
        """Build role-assignment snapshots for classic administrators (ARM)."""
        data = await self._arm_get(
            f"{_ARM_BASE}/subscriptions/{self._subscription_id}/providers/"
            "Microsoft.Authorization/classicAdministrators?api-version=2015-07-01"
        )
        snapshots: list[ResourceSnapshot] = []
        for admin in data.get("value", []) or []:
            props = admin.get("properties") or {}
            email = str(props.get("emailAddress") or admin.get("name") or "")
            role = str(props.get("role") or "ClassicAdministrator")
            if not email:
                continue
            snapshots.append(
                ResourceSnapshot(
                    subscription_id=self._subscription_id,
                    resource_group="unknown",
                    resource_type=_ROLE_ASSIGNMENT_TYPE,
                    resource_name=email,
                    region="global",
                    provider=CloudProvider.AZURE,
                    data_tier=DataTier.TIER1_NATIVE,
                    config={
                        "role_definition_name": role,
                        "principal_type": "User",
                        "scope": f"/subscriptions/{self._subscription_id}",
                        "is_classic_admin": True,
                    },
                )
            )
        return snapshots

    @staticmethod
    def _parse_iso(value: str) -> datetime | None:
        """Parse an ISO-8601 timestamp into an aware UTC datetime."""
        if not value:
            return None
        try:
            cleaned = value.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(cleaned)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # HTTP layer (patched in tests)
    # ------------------------------------------------------------------

    async def _get_token(self, scope: str) -> str:
        """Acquire a bearer token, supporting sync and async credentials."""
        import inspect

        token = self._credential.get_token(scope)
        if inspect.isawaitable(token):
            token = await token
        return str(token.token)

    async def _graph_get(self, path: str) -> dict[str, Any]:
        """GET a Microsoft Graph resource and return the parsed JSON body."""
        return await self._request("GET", path, _GRAPH_SCOPE, None)

    async def _graph_post(
        self, path: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """POST to a Microsoft Graph resource and return the parsed JSON body."""
        return await self._request("POST", path, _GRAPH_SCOPE, body)

    async def _arm_get(self, path: str) -> dict[str, Any]:
        """GET an Azure Resource Manager resource and return the JSON body."""
        return await self._request("GET", path, _ARM_SCOPE, None)

    async def _request(
        self,
        method: str,
        url: str,
        scope: str,
        body: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Perform an authenticated HTTP request and return the JSON body."""
        import aiohttp

        token = await self._get_token(scope)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        async with aiohttp.ClientSession() as session, session.request(
            method, url, headers=headers, json=body
        ) as resp:
            resp.raise_for_status()
            data: dict[str, Any] = await resp.json()
            return data
