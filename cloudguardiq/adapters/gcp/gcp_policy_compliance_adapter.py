"""CloudGuardIQ - GCP policy compliance adapter.

Ingests compliance-style findings from Google Security Command Center (SCC),
normalises them into FindingResult records, and feeds the existing
CloudGuardIQ pipeline.

All GCP API calls are best-effort and never raise to callers. Missing APIs,
insufficient permissions, or transport failures return empty results with
warnings so scans continue.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any

from cloudguardiq.adapters.base import AdapterBase
from cloudguardiq.core.enums import CloudProvider, DataTier, FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot

logger = logging.getLogger(__name__)

# Security Command Center posture families routed to our scorecard framework IDs.
FRAMEWORK_POSTURES: dict[str, str] = {
    "CIS_AZURE": "cis",
    "NIST_800_53": "nist",
    "PCI_DSS": "pci",
    "ISO_27001": "iso",
    "SOC2": "soc2",
    "HIPAA": "hipaa",
}

_POSTURE_TO_FRAMEWORK: dict[str, str] = {
    v.lower(): k for k, v in FRAMEWORK_POSTURES.items()
}

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFORMATIONAL,
}

_CONTROL_TOKEN_RE = re.compile(r"([A-Za-z]{1,6}-?\d+(?:\.\d+)*)$")


class GCPPolicyComplianceAdapter(AdapterBase):
    """Read compliance state from Google Security Command Center findings.

    Args:
        project_id: GCP project id.
        credentials: Optional Google auth credentials.
        postures: Optional explicit list of posture family identifiers.
    """

    def __init__(
        self,
        *,
        project_id: str,
        credentials: Any | None = None,
        postures: list[str] | None = None,
    ) -> None:
        self._project_id = project_id
        self._credentials = credentials
        self._postures_explicit = postures is not None
        self._postures = (
            list(postures)
            if postures is not None
            else list(FRAMEWORK_POSTURES.values())
        )

    async def scan(self) -> list[ResourceSnapshot]:
        """Return an empty list.

        Required by AdapterBase, but this adapter emits compliance findings via
        fetch_findings and does not enumerate resource snapshots.
        """
        return []

    async def get_api_contract(self) -> dict[str, Any]:
        """Return a best-effort SCC finding field fingerprint."""
        targets = self._postures[:1]
        schema: dict[str, str] = {}
        if not targets:
            return {"provider": "gcp", "endpoint": "scc.list_findings", "schema": {}}
        rows = await self._query_non_compliant_findings(targets[0])
        if rows:
            schema = {k: type(v).__name__ for k, v in rows[0].items()}
        return {
            "provider": "gcp",
            "endpoint": "scc.list_findings",
            "schema": schema,
        }

    async def validate_connection(self) -> bool:
        """Return True when SCC can list at least one finding."""

        def _check() -> bool:
            try:
                client = self._scc_client()
                req = {
                    "parent": f"projects/{self._project_id}/sources/-",
                    "filter": "state=\"ACTIVE\"",
                    "page_size": 1,
                }
                list(client.list_findings(request=req))
                return True
            except Exception as exc:  # noqa: BLE001
                logger.warning("GCP policy validate_connection failed: %s", exc)
                return False

        return await asyncio.to_thread(_check)

    async def list_resources(self, subscription_id: str) -> list[ResourceSnapshot]:
        """Not applicable for this adapter; returns an empty list."""
        return []

    async def get_resource(self, resource_id: str) -> ResourceSnapshot | None:
        """Not applicable for this adapter; returns None."""
        return None

    async def get_cost(self, resource_id: str) -> float:
        """Not applicable for compliance-only findings."""
        return 0.0

    async def enrich_with_defender(
        self, snapshots: list[ResourceSnapshot]
    ) -> list[ResourceSnapshot]:
        """Defender is Azure-only; return snapshots unchanged."""
        return snapshots

    async def get_raw_properties(self, resource_id: str) -> dict[str, Any]:
        """Not applicable for this adapter; returns an empty dict."""
        return {}

    async def fetch_findings(self) -> list[FindingResult]:
        """Fetch non-compliant SCC findings and convert to FindingResult.

        Returns:
            Deduplicated compliance findings. Never raises.
        """
        try:
            available = await self._list_enabled_postures()
            if not available:
                return []

            available_by_lower = {s.lower(): s for s in available}
            if self._postures_explicit:
                targets = [
                    available_by_lower[p.lower()]
                    for p in self._postures
                    if p.lower() in available_by_lower
                ]
            else:
                targets = sorted(available)

            deduped: dict[tuple[str, str], FindingResult] = {}
            for posture in targets:
                rows = await self._query_non_compliant_findings(posture)
                for row in rows:
                    finding = self._to_finding(row, posture)
                    if finding is None:
                        continue
                    resource_id = self._row_resource_id(row) or ""
                    control_key = self._row_control_key(row) or ""
                    key = (resource_id, control_key)
                    existing = deduped.get(key)
                    if existing is None or finding.detected_at >= existing.detected_at:
                        deduped[key] = finding

            findings = list(deduped.values())
            logger.info(
                "GCP policy compliance ingestion produced %d finding(s) for %s",
                len(findings),
                self._project_id,
            )
            return findings
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "GCP policy compliance ingestion failed for %s: %s",
                self._project_id,
                exc,
            )
            return []

    async def _list_enabled_postures(self) -> set[str]:
        """Return enabled posture families discovered from active SCC findings.

        Returns an empty set on any API or permission failure.
        """

        def _list() -> set[str]:
            detected: set[str] = set()
            try:
                client = self._scc_client()
                req = {
                    "parent": f"projects/{self._project_id}/sources/-",
                    "filter": "state=\"ACTIVE\"",
                    "page_size": 100,
                }
                for item in client.list_findings(request=req):
                    row = self._finding_to_dict(item)
                    family = self._detect_posture_family(row)
                    if family:
                        detected.add(family)
                return detected
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to list GCP posture families for %s: %s",
                    self._project_id,
                    exc,
                )
                return set()

        return await asyncio.to_thread(_list)

    async def _query_non_compliant_findings(self, posture: str) -> list[dict[str, Any]]:
        """Return ACTIVE compliance-like findings for one posture family."""

        def _query() -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            try:
                client = self._scc_client()
                req = {
                    "parent": f"projects/{self._project_id}/sources/-",
                    "filter": "state=\"ACTIVE\"",
                    "page_size": 200,
                }
                for item in client.list_findings(request=req):
                    row = self._finding_to_dict(item)
                    family = self._detect_posture_family(row)
                    if family and family.lower() == posture.lower():
                        rows.append(row)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to query GCP compliance findings for %s: %s",
                    posture,
                    exc,
                )
                return []
            return rows

        return await asyncio.to_thread(_query)

    def _to_finding(self, row: dict[str, Any], posture: str) -> FindingResult | None:
        """Convert one SCC row into a FindingResult."""
        resource_id = self._row_resource_id(row)
        control_key = self._row_control_key(row)
        if not resource_id or not control_key:
            return None

        framework_id = _POSTURE_TO_FRAMEWORK.get(posture.lower())
        control_id = self._extract_control_id(control_key)
        if framework_id and control_id:
            compliance_frameworks = [f"{framework_id}:{control_id}"]
        elif framework_id:
            compliance_frameworks = [framework_id]
        else:
            compliance_frameworks = []

        rule_token = re.sub(r"[^A-Za-z0-9]+", "_", control_key).strip("_")
        rule_id = f"GCPPOL-{rule_token or 'CONTROL'}"
        title = str(row.get("category") or row.get("name") or "GCP compliance control failed")

        severity_label = str(row.get("severity") or "MEDIUM").upper()
        severity = _SEVERITY_MAP.get(severity_label, Severity.MEDIUM)

        resource_type = self._row_resource_type(row)
        resource_name = resource_id.rsplit("/", 1)[-1] if "/" in resource_id else resource_id

        return FindingResult(
            finding_id=AdapterBase.build_finding_id(rule_id, resource_id),
            resource_snapshot=ResourceSnapshot(
                tenant_id="",
                provider=CloudProvider.GCP,
                subscription_id=self._project_id,
                resource_group="gcp-global",
                resource_type=resource_type,
                resource_name=resource_name,
                region=str(row.get("location") or "global"),
                config={},
                tags={},
                data_tier=DataTier.TIER1_NATIVE,
            ),
            rule_id=rule_id,
            rule_name=title,
            severity=severity,
            finding_type=FindingType.COMPLIANCE,
            description=str(row.get("description") or title),
            evidence={
                "finding_name": str(row.get("name") or ""),
                "category": str(row.get("category") or ""),
                "event_time": str(row.get("event_time") or ""),
                "external_uri": str(row.get("external_uri") or ""),
                "source_properties": dict(row.get("source_properties") or {}),
            },
            compliance_frameworks=compliance_frameworks,
            waste_monthly_usd=0.0,
            detected_at=self._parse_timestamp(row.get("event_time") or row.get("create_time")),
        )

    def _scc_client(self) -> Any:
        from google.cloud import securitycenter_v1  # type: ignore[import-not-found]

        return securitycenter_v1.SecurityCenterClient(credentials=self._credentials)

    @staticmethod
    def _finding_to_dict(item: Any) -> dict[str, Any]:
        if isinstance(item, dict):
            return item

        finding = getattr(item, "finding", None)
        if finding is not None:
            as_dict = getattr(finding, "to_dict", None)
            if callable(as_dict):
                try:
                    out = dict(as_dict())
                    resource_name = getattr(item, "resource_name", "")
                    if resource_name and "resource_name" not in out:
                        out["resource_name"] = resource_name
                    return out
                except Exception:  # pragma: no cover - defensive
                    pass

        to_dict = getattr(item, "to_dict", None)
        if callable(to_dict):
            try:
                return dict(to_dict())
            except Exception:  # pragma: no cover - defensive
                pass

        return {
            k: v
            for k, v in vars(item).items()
            if not k.startswith("_")
        }

    @staticmethod
    def _detect_posture_family(row: dict[str, Any]) -> str | None:
        text = " ".join(
            str(row.get(k) or "")
            for k in ("category", "name", "description")
        ).lower()
        for family in FRAMEWORK_POSTURES.values():
            if family in text:
                return family
        return None

    @staticmethod
    def _row_resource_id(row: dict[str, Any]) -> str | None:
        value = row.get("resource_name") or row.get("resourceName")
        if isinstance(value, str) and value:
            return value
        source_props = row.get("source_properties")
        if isinstance(source_props, dict):
            for key in ("resourceName", "resource_name", "resource"):
                candidate = source_props.get(key)
                if isinstance(candidate, str) and candidate:
                    return candidate
        return None

    @staticmethod
    def _row_resource_type(row: dict[str, Any]) -> str:
        source_props = row.get("source_properties")
        if isinstance(source_props, dict):
            rtype = source_props.get("resourceType") or source_props.get("resource_type")
            if isinstance(rtype, str) and rtype:
                return rtype
        return "google.cloud.resource"

    @staticmethod
    def _row_control_key(row: dict[str, Any]) -> str | None:
        for key in ("category", "name"):
            value = row.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _extract_control_id(control_key: str) -> str:
        match = _CONTROL_TOKEN_RE.search(control_key)
        if match:
            return match.group(1)
        token = control_key.rsplit("/", 1)[-1]
        return token or control_key

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str) and value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed
            except ValueError:
                pass
        return datetime.now(timezone.utc)


__all__ = ["GCPPolicyComplianceAdapter", "FRAMEWORK_POSTURES"]
