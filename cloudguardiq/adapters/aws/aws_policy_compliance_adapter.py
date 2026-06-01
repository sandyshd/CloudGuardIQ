"""CloudGuardIQ - AWS policy compliance adapter.

Ingests non-compliant control evaluations from AWS Security Hub standards,
normalises each row into a FindingResult, and exposes them to the existing
CloudGuardIQ scoring/remediation pipeline.

All AWS API calls are best-effort and never raise to callers. Missing
permissions, disabled Security Hub, or transport failures return empty
results with warnings so scans keep running.
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

# AWS Security Hub standards ARNs.
FRAMEWORK_STANDARDS: dict[str, str] = {
    "CIS_AZURE": "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0",
    "NIST_800_53": "arn:aws:securityhub:::standards/nist-800-53/v/5.0.0",
    "PCI_DSS": "arn:aws:securityhub:::standards/pci-dss/v/3.2.1",
}

_STANDARD_TO_FRAMEWORK: dict[str, str] = {
    v.lower(): k for k, v in FRAMEWORK_STANDARDS.items()
}

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.INFORMATIONAL,
}

_CONTROL_TOKEN_RE = re.compile(r"([A-Za-z]{1,6}-?\d+(?:\.\d+)*)$")


class AWSPolicyComplianceAdapter(AdapterBase):
    """Read compliance state from AWS Security Hub standards.

    Args:
        account_id: AWS account id.
        region: AWS region for Security Hub API.
        session: Optional prebuilt boto3 session.
        standards: Optional explicit list of Security Hub standards ARNs.
    """

    def __init__(
        self,
        *,
        account_id: str,
        region: str = "us-east-1",
        session: Any | None = None,
        standards: list[str] | None = None,
    ) -> None:
        self._account_id = account_id
        self._region = region
        self._session = session
        self._standards_explicit = standards is not None
        self._standards = (
            list(standards)
            if standards is not None
            else list(FRAMEWORK_STANDARDS.values())
        )

    async def scan(self) -> list[ResourceSnapshot]:
        """Return an empty list.

        Required by AdapterBase, but this adapter emits compliance findings via
        fetch_findings and does not enumerate resource snapshots.
        """
        return []

    async def get_api_contract(self) -> dict[str, Any]:
        """Return a best-effort field fingerprint for Security Hub findings."""
        targets = self._standards[:1]
        schema: dict[str, str] = {}
        if not targets:
            return {"provider": "aws", "endpoint": "securityhub.get_findings", "schema": {}}
        rows = await self._query_non_compliant_findings(targets[0])
        if rows:
            schema = {k: type(v).__name__ for k, v in rows[0].items()}
        return {
            "provider": "aws",
            "endpoint": "securityhub.get_findings",
            "schema": schema,
        }

    async def validate_connection(self) -> bool:
        """Return True when Security Hub standards can be listed."""

        def _check() -> bool:
            try:
                client = self._securityhub_client()
                client.get_enabled_standards(MaxResults=1)
                return True
            except Exception as exc:  # noqa: BLE001
                logger.warning("AWS policy validate_connection failed: %s", exc)
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
        """Fetch non-compliant standards findings and convert to FindingResult.

        Returns:
            Deduplicated compliance findings. Never raises.
        """
        try:
            assigned = await self._list_enabled_standards()
            if not assigned:
                return []

            assigned_by_lower = {s.lower(): s for s in assigned}
            if self._standards_explicit:
                targets = [
                    assigned_by_lower[s.lower()]
                    for s in self._standards
                    if s.lower() in assigned_by_lower
                ]
            else:
                targets = sorted(assigned)

            deduped: dict[tuple[str, str], FindingResult] = {}
            for standard_arn in targets:
                rows = await self._query_non_compliant_findings(standard_arn)
                for row in rows:
                    finding = self._to_finding(row, standard_arn)
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
                "AWS policy compliance ingestion produced %d finding(s) for %s",
                len(findings),
                self._account_id,
            )
            return findings
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "AWS policy compliance ingestion failed for %s: %s",
                self._account_id,
                exc,
            )
            return []

    async def _list_enabled_standards(self) -> set[str]:
        """Return enabled Security Hub standards ARNs.

        Returns an empty set on any API or permission failure.
        """

        def _list() -> set[str]:
            enabled: set[str] = set()
            try:
                client = self._securityhub_client()
                next_token: str | None = None
                while True:
                    kwargs: dict[str, Any] = {"MaxResults": 50}
                    if next_token:
                        kwargs["NextToken"] = next_token
                    resp = client.get_enabled_standards(**kwargs)
                    for item in resp.get("StandardsSubscriptions") or []:
                        standards_arn = item.get("StandardsArn")
                        if isinstance(standards_arn, str) and standards_arn:
                            enabled.add(standards_arn)
                    next_token = resp.get("NextToken")
                    if not isinstance(next_token, str) or not next_token:
                        break
                return enabled
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to list AWS enabled standards for %s: %s",
                    self._account_id,
                    exc,
                )
                return set()

        return await asyncio.to_thread(_list)

    async def _query_non_compliant_findings(self, standard_arn: str) -> list[dict[str, Any]]:
        """Return ACTIVE + FAILED Security Hub findings for one standard.

        Returns an empty list on any error.
        """

        def _query() -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            try:
                client = self._securityhub_client()
                next_token: str | None = None
                while True:
                    kwargs: dict[str, Any] = {
                        "MaxResults": 100,
                        "Filters": {
                            "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
                            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                            "StandardsArn": [{"Value": standard_arn, "Comparison": "EQUALS"}],
                        },
                    }
                    if next_token:
                        kwargs["NextToken"] = next_token
                    resp = client.get_findings(**kwargs)
                    for finding in resp.get("Findings") or []:
                        if isinstance(finding, dict):
                            rows.append(finding)
                    next_token = resp.get("NextToken")
                    if not isinstance(next_token, str) or not next_token:
                        break
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Failed to query AWS compliance findings for %s: %s",
                    standard_arn,
                    exc,
                )
                return []
            return rows

        return await asyncio.to_thread(_query)

    def _to_finding(self, row: dict[str, Any], standard_arn: str) -> FindingResult | None:
        """Convert a Security Hub finding row to FindingResult."""
        resource_id = self._row_resource_id(row)
        control_key = self._row_control_key(row)
        if not resource_id or not control_key:
            return None

        title = str(row.get("Title") or "AWS compliance control failed")
        rule_token = re.sub(r"[^A-Za-z0-9]+", "_", control_key).strip("_")
        rule_id = f"AWSPOL-{rule_token or 'CONTROL'}"

        severity_label = str((row.get("Severity") or {}).get("Label") or "MEDIUM").upper()
        severity = _SEVERITY_MAP.get(severity_label, Severity.MEDIUM)

        framework_id = _STANDARD_TO_FRAMEWORK.get(standard_arn.lower())
        control_id = self._extract_control_id(control_key)
        if framework_id and control_id:
            compliance_frameworks = [f"{framework_id}:{control_id}"]
        elif framework_id:
            compliance_frameworks = [framework_id]
        else:
            compliance_frameworks = []

        resource_type = self._row_resource_type(row)
        resource_name = resource_id.rsplit("/", 1)[-1] if "/" in resource_id else resource_id

        finding = FindingResult(
            finding_id=AdapterBase.build_finding_id(rule_id, resource_id),
            resource_snapshot=ResourceSnapshot(
                tenant_id="",
                provider=CloudProvider.AWS,
                subscription_id=self._account_id,
                resource_group="aws-global",
                resource_type=resource_type,
                resource_name=resource_name,
                region=self._region,
                config={},
                tags={},
                data_tier=DataTier.TIER1_NATIVE,
            ),
            rule_id=rule_id,
            rule_name=title,
            severity=severity,
            finding_type=FindingType.COMPLIANCE,
            description=str(row.get("Description") or title),
            evidence={
                "finding_arn": str(row.get("Id") or ""),
                "product_arn": str(row.get("ProductArn") or ""),
                "compliance_status": str((row.get("Compliance") or {}).get("Status") or ""),
                "generator_id": str(row.get("GeneratorId") or ""),
                "updated_at": str(row.get("UpdatedAt") or ""),
            },
            compliance_frameworks=compliance_frameworks,
            waste_monthly_usd=0.0,
            detected_at=self._parse_timestamp(row.get("UpdatedAt") or row.get("CreatedAt")),
        )
        return finding

    def _securityhub_client(self) -> Any:
        session = self._session
        if session is None:
            from cloudguardiq.adapters.aws.adapter import _require_boto3

            boto3 = _require_boto3()
            session = boto3.Session(region_name=self._region)
            self._session = session
        return session.client("securityhub", region_name=self._region)

    @staticmethod
    def _row_resource_id(row: dict[str, Any]) -> str | None:
        resources = row.get("Resources") or []
        if isinstance(resources, list) and resources:
            first = resources[0]
            if isinstance(first, dict):
                rid = first.get("Id")
                if isinstance(rid, str) and rid:
                    return rid
        return None

    @staticmethod
    def _row_resource_type(row: dict[str, Any]) -> str:
        resources = row.get("Resources") or []
        if isinstance(resources, list) and resources:
            first = resources[0]
            if isinstance(first, dict):
                rtype = first.get("Type")
                if isinstance(rtype, str) and rtype:
                    return rtype
        return "AWS::Unknown::Resource"

    @staticmethod
    def _row_control_key(row: dict[str, Any]) -> str | None:
        for key in ("GeneratorId", "Title"):
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


__all__ = ["AWSPolicyComplianceAdapter", "FRAMEWORK_STANDARDS"]
