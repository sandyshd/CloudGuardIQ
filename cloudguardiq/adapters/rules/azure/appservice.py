"""CloudGuardIQ — Azure App Service security rules."""

from __future__ import annotations

from cloudguardiq.adapters.rules.base import PolicyRule
from cloudguardiq.core.enums import FindingType, Severity
from cloudguardiq.core.models import FindingResult, ResourceSnapshot


class AppServiceHttpsOnlyRule(PolicyRule):
    """APP-001: Flag App Service apps that do not enforce HTTPS."""

    rule_id: str = "APP-001"
    rule_name: str = "App Service does not enforce HTTPS"
    resource_types: list[str] = ["Microsoft.Web/sites"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_9.10",
        "NIST_SC-8",
        "PCI_DSS_4.1",
        "HIPAA_164.312(e)(1)",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when ``https_only`` is False."""
        if snapshot.config.get("https_only") is True:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"App Service '{snapshot.resource_name}' accepts plain HTTP "
                "traffic. Enable HTTPS-only."
            ),
            evidence={"https_only": snapshot.config.get("https_only", False)},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class AppServiceMinTlsRule(PolicyRule):
    """APP-002: Flag App Service apps with minimum TLS below 1.2."""

    rule_id: str = "APP-002"
    rule_name: str = "App Service minimum TLS below 1.2"
    resource_types: list[str] = ["Microsoft.Web/sites"]
    severity: Severity = Severity.HIGH
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_9.3",
        "NIST_SC-8",
        "PCI_DSS_4.1",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when minimum TLS is < 1.2."""
        version = str(snapshot.config.get("min_tls_version", "")).strip()
        if version in ("1.2", "1.3"):
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"App Service '{snapshot.resource_name}' allows TLS "
                f"versions below 1.2 (current: '{version or 'unset'}')."
            ),
            evidence={"min_tls_version": version},
            compliance_frameworks=list(self.compliance_frameworks),
        )


class AppServiceAuthDisabledRule(PolicyRule):
    """APP-003: Flag App Service apps with no authentication configured."""

    rule_id: str = "APP-003"
    rule_name: str = "App Service authentication disabled"
    resource_types: list[str] = ["Microsoft.Web/sites"]
    severity: Severity = Severity.MEDIUM
    finding_type: FindingType = FindingType.SECURITY
    compliance_frameworks: list[str] = [
        "CIS_9.1",
        "NIST_AC-3",
        "ISO_27001_A.5.15",
    ]

    def evaluate(self, snapshot: ResourceSnapshot) -> FindingResult | None:
        """Return a finding when both EasyAuth and client cert are off."""
        auth_enabled = bool(snapshot.config.get("auth_enabled"))
        client_cert = bool(snapshot.config.get("client_cert_enabled"))
        if auth_enabled or client_cert:
            return None
        return FindingResult(
            resource_snapshot=snapshot,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            finding_type=self.finding_type,
            description=(
                f"App Service '{snapshot.resource_name}' has no "
                "authentication or client certificate requirement enabled."
            ),
            evidence={
                "auth_enabled": auth_enabled,
                "client_cert_enabled": client_cert,
            },
            compliance_frameworks=list(self.compliance_frameworks),
        )
