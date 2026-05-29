"""CloudGuardIQ — Azure SQL / PostgreSQL security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class SqlPublicNetworkAccessRule(PolicyRule):
    """SQL-001: Flag SQL servers whose public network access is enabled."""

    rule_id: str = "SQL-001"
    rule_name: str = "SQL server public network access enabled"
    resource_types: list[str] = [
        "Microsoft.Sql/servers",
        "Microsoft.DBforPostgreSQL/flexibleServers",
        "Microsoft.DBforPostgreSQL/servers",
    ]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_4.1",
        "NIST_SC-7",
        "ISO_27001_A.8.20",
        "PCI_DSS_1.3.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``public_network_access`` is enabled."""
        value = str(snapshot.config.get("public_network_access", "")).lower()
        if value not in ("enabled", "true"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"SQL server '{snapshot.resource_name}' allows public "
                "network access. Restrict via private endpoints or firewall."
            ),
            evidence={"public_network_access": value},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class SqlMinTlsVersionRule(PolicyRule):
    """SQL-002: Flag SQL servers with minimum TLS version below 1.2."""

    rule_id: str = "SQL-002"
    rule_name: str = "SQL server minimum TLS version below 1.2"
    resource_types: list[str] = [
        "Microsoft.Sql/servers",
        "Microsoft.DBforPostgreSQL/flexibleServers",
        "Microsoft.DBforPostgreSQL/servers",
    ]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_4.1.3",
        "NIST_SC-8",
        "PCI_DSS_4.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``minimal_tls_version`` is unset or < 1.2."""
        version = str(snapshot.config.get("minimal_tls_version", "")).strip()
        if version in ("1.2", "1.3", "TLS1_2", "TLS1_3"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"SQL server '{snapshot.resource_name}' accepts TLS "
                f"versions below 1.2 (current: '{version or 'unset'}')."
            ),
            evidence={"minimal_tls_version": version},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class SqlAuditingDisabledRule(PolicyRule):
    """SQL-003: Flag SQL servers with auditing disabled."""

    rule_id: str = "SQL-003"
    rule_name: str = "SQL server auditing disabled"
    resource_types: list[str] = [
        "Microsoft.Sql/servers",
        "Microsoft.DBforPostgreSQL/flexibleServers",
    ]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.COMPLIANCE
    compliance_frameworks: list[str] = [
        "CIS_4.1.1",
        "NIST_AU-2",
        "SOC2_CC7.2",
        "ISO_27001_A.8.15",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when auditing state is not ``Enabled``."""
        state = str(snapshot.config.get("auditing_state", "")).lower()
        if state == "enabled":
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"SQL server '{snapshot.resource_name}' has auditing "
                "disabled. Enable to capture database activity."
            ),
            evidence={"auditing_state": state or "disabled"},
            compliance_frameworks=list(self.compliance_frameworks),
        )
