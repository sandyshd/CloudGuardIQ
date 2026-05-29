"""Compliance report PDF generation using reportlab.

Renders a multi-section PDF for a single framework using the
``compute_scorecard`` output and the raw FindingResult list. The output is
a self-contained byte string suitable for upload to Azure Blob Storage.
"""

from __future__ import annotations

import io
import logging
from collections.abc import Iterable
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from cloudguardiq.compliance.scorecard import (
    FRAMEWORKS,
    FrameworkDef,
    FrameworkScore,
    _classify,  # noqa: PLC2701 -- internal helper used to map tags to control ids
    compute_scorecard,
)
from cloudguardiq.core.enums import CloudProvider, FindingStatus, Severity
from cloudguardiq.core.models import FindingResult

logger = logging.getLogger(__name__)


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}

_CIS_AZURE_CATEGORY_LABELS: dict[str, str] = {
    "1": "Identity and Access Management",
    "2": "Microsoft Defender for Cloud",
    "3": "Storage Accounts",
    "4": "Database Services",
    "5": "Logging and Monitoring",
    "6": "Networking",
    "7": "Virtual Machines",
    "8": "Key Vault",
    "9": "App Service",
    "10": "Miscellaneous",
}

_NIST_800_53_CATEGORY_LABELS: dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "PII Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}

_ISO_27001_CATEGORY_LABELS: dict[str, str] = {
    "A.5": "Information security policies",
    "A.6": "Organization of information security",
    "A.7": "Human resource security",
    "A.8": "Asset management",
    "A.9": "Access control",
    "A.10": "Cryptography",
    "A.11": "Physical and environmental security",
    "A.12": "Operations security",
    "A.13": "Communications security",
    "A.14": "System acquisition, development and maintenance",
    "A.15": "Supplier relationships",
    "A.16": "Information security incident management",
    "A.17": "Information security aspects of business continuity",
    "A.18": "Compliance",
}

_PCI_DSS_CATEGORY_LABELS: dict[str, str] = {
    "1": "Install and maintain network security controls",
    "2": "Apply secure configurations",
    "3": "Protect stored account data",
    "4": "Protect cardholder data with strong cryptography during transmission",
    "5": "Protect systems and networks from malicious software",
    "6": "Develop and maintain secure systems and software",
    "7": "Restrict access to system components and cardholder data",
    "8": "Identify users and authenticate access to system components",
    "9": "Restrict physical access to cardholder data",
    "10": "Log and monitor all access to system components and cardholder data",
    "11": "Test security of systems and networks regularly",
    "12": "Support information security with organizational policies and programs",
}

_SOC2_CATEGORY_LABELS: dict[str, str] = {
    "CC1": "Control Environment",
    "CC2": "Communication and Information",
    "CC3": "Risk Assessment",
    "CC4": "Monitoring Activities",
    "CC5": "Control Activities",
    "CC6": "Logical and Physical Access Controls",
    "CC7": "System Operations",
    "CC8": "Change Management",
    "CC9": "Risk Mitigation",
}

_HIPAA_CATEGORY_LABELS: dict[str, str] = {
    "164.308": "Administrative Safeguards",
    "164.310": "Physical Safeguards",
    "164.312": "Technical Safeguards",
    "164.314": "Organizational Requirements",
    "164.316": "Policies and Procedures",
}

_FRAMEWORK_CATEGORY_LABELS: dict[str, dict[str, str]] = {
    "CIS_AZURE": _CIS_AZURE_CATEGORY_LABELS,
    "NIST_800_53": _NIST_800_53_CATEGORY_LABELS,
    "ISO_27001": _ISO_27001_CATEGORY_LABELS,
    "PCI_DSS": _PCI_DSS_CATEGORY_LABELS,
    "SOC2": _SOC2_CATEGORY_LABELS,
    "HIPAA": _HIPAA_CATEGORY_LABELS,
}


def _category_for(framework_id: str, control_id: str) -> str:
    """Return the category bucket for a control id under *framework_id*."""
    if not control_id:
        return "Other"
    if framework_id in ("CIS_AZURE", "PCI_DSS"):
        return control_id.split(".", 1)[0]
    if framework_id == "NIST_800_53":
        return control_id.split("-", 1)[0]
    if framework_id == "SOC2":
        return control_id.split(".", 1)[0]
    if framework_id == "ISO_27001":
        parts = control_id.split(".")
        return ".".join(parts[:2]) if len(parts) >= 2 else control_id
    if framework_id == "HIPAA":
        head = control_id.split("(", 1)[0]
        return head.rstrip(".")
    return control_id


def _category_label(framework_id: str, category: str) -> str:
    """Map a category bucket to a human-readable display label."""
    table = _FRAMEWORK_CATEGORY_LABELS.get(framework_id, {})
    label = table.get(category)
    if label:
        return f"{category} — {label}"
    return category


_SEVERITY_COLOR: dict[Severity, colors.Color] = {
    Severity.CRITICAL: colors.HexColor("#b91c1c"),
    Severity.HIGH: colors.HexColor("#c2410c"),
    Severity.MEDIUM: colors.HexColor("#b45309"),
    Severity.LOW: colors.HexColor("#0369a1"),
    Severity.INFORMATIONAL: colors.HexColor("#475569"),
}


def _framework_def(framework_id: str) -> FrameworkDef:
    for fw in FRAMEWORKS:
        if fw.id == framework_id:
            return fw
    raise ValueError(f"Unknown framework_id: {framework_id}")


class ComplianceReportGenerator:
    """Render a compliance report PDF for a single framework."""

    def __init__(self, *, product_name: str = "CloudGuardIQ") -> None:
        self._product_name = product_name
        self._styles = getSampleStyleSheet()
        self._styles.add(
            ParagraphStyle(
                name="CoverTitle",
                fontName="Helvetica-Bold",
                fontSize=32,
                leading=38,
                textColor=colors.HexColor("#0f172a"),
                spaceAfter=12,
            )
        )
        self._styles.add(
            ParagraphStyle(
                name="CoverSubtitle",
                fontName="Helvetica",
                fontSize=16,
                leading=20,
                textColor=colors.HexColor("#475569"),
                spaceAfter=24,
            )
        )
        self._styles.add(
            ParagraphStyle(
                name="SectionHeader",
                fontName="Helvetica-Bold",
                fontSize=18,
                leading=22,
                textColor=colors.HexColor("#0f172a"),
                spaceBefore=8,
                spaceAfter=10,
            )
        )
        self._styles.add(
            ParagraphStyle(
                name="ScoreBadge",
                fontName="Helvetica-Bold",
                fontSize=64,
                leading=70,
                textColor=colors.HexColor("#0d9488"),
                alignment=1,
            )
        )
        self._styles.add(
            ParagraphStyle(
                name="Disclaimer",
                fontName="Helvetica-Oblique",
                fontSize=9,
                leading=12,
                textColor=colors.HexColor("#475569"),
                alignment=1,
            )
        )

    async def generate(
        self,
        *,
        subscription_id: str,
        framework: str,
        findings: Iterable[FindingResult],
        customer_name: str = "",
        providers: set[CloudProvider] | None = None,
        generated_by: str = "",
        report_id: str = "",
    ) -> bytes:
        """Generate a compliance report PDF and return its raw bytes.

        ``providers`` restricts the rule catalogue used in the denominator
        to the clouds the subscription has connected, matching the
        ``/compliance/scorecard`` endpoint that powers the Compliance page.
        """
        framework_id = self._normalise_framework(framework)
        fw = _framework_def(framework_id)
        findings_list = list(findings)

        scorecard = compute_scorecard(findings_list, providers=providers)
        score_row = next(
            (row for row in scorecard if row.framework_id == framework_id),
            None,
        )
        if score_row is None:
            # The catalogue has no controls for the requested framework.
            # Emit a minimal record so the PDF still renders cleanly.
            score_row = FrameworkScore(
                framework_id=fw.id,
                label=fw.label,
                short_label=fw.short_label,
                prefixes=fw.prefixes,
                controls_total=0,
                controls_failed=0,
                controls_passed=0,
                score=100,
                open_findings=0,
                severity_breakdown=__import__(
                    "cloudguardiq.compliance.scorecard",
                    fromlist=["SeverityBreakdown"],
                ).SeverityBreakdown(),
            )

        relevant = [
            f for f in findings_list
            if self._is_open(f) and self._has_framework_tag(f, fw)
        ]
        relevant.sort(key=self._finding_sort_key)

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=LETTER,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            title=f"{fw.short_label} Compliance Readiness Report",
            author=self._product_name,
        )

        story: list = []
        story += self._cover_page(fw, score_row, customer_name, subscription_id)
        story.append(PageBreak())
        story += self._scope_and_methodology(
            fw=fw,
            score_row=score_row,
            subscription_id=subscription_id,
            customer_name=customer_name,
            providers=providers,
            generated_by=generated_by,
            report_id=report_id,
        )
        story.append(PageBreak())
        story += self._executive_summary(fw, score_row, relevant)
        story.append(PageBreak())
        story += self._score_breakdown(fw, score_row, relevant)
        story.append(PageBreak())
        story += self._critical_findings(relevant[:10])
        story.append(PageBreak())
        story += self._controls_list(fw, score_row, relevant)
        story.append(PageBreak())
        story += self._remediation_roadmap(relevant)
        story.append(PageBreak())
        story += self._appendix(relevant)

        doc.build(story)
        return buf.getvalue()

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _scope_and_methodology(
        self,
        *,
        fw: FrameworkDef,
        score_row: FrameworkScore,
        subscription_id: str,
        customer_name: str,
        providers: set[CloudProvider] | None,
        generated_by: str,
        report_id: str,
    ) -> list:
        styles = self._styles
        provider_labels = (
            ", ".join(sorted(p.value for p in providers)) if providers else "All connected clouds"
        )
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        purpose = (
            f"This document is an automated <b>compliance readiness</b> report "
            f"produced by {self._product_name}. It summarises how the configuration "
            f"of the in-scope cloud resources aligns with the technical controls "
            f"of <b>{fw.label}</b> that can be observed directly from cloud "
            f"provider APIs. It is intended for internal readiness, gap analysis, "
            f"and to brief auditors &mdash; it is <b>not</b> an audit opinion, "
            f"attestation, or certification."
        )
        coverage = (
            f"{self._product_name} evaluates <b>{score_row.controls_total}</b> "
            f"{fw.short_label} controls automatically. Controls outside this "
            f"catalogue (for example controls that require interviews, signed "
            f"policies, physical inspection, or evidence outside the cloud "
            f"provider APIs) are <b>Not Assessed</b> and must be reviewed "
            f"through other means before relying on this report for audit "
            f"purposes."
        )
        methodology = (
            "Findings are produced by querying provider configuration through "
            "Azure Resource Graph (and equivalent read-only APIs on other "
            "clouds) and, where available, enriching with Microsoft Defender "
            "for Cloud posture data. A control is marked <b>Fail</b> if one or "
            "more in-scope resources have an open finding mapped to that "
            "control, and <b>Pass</b> otherwise. The readiness score is "
            "computed as <i>passing controls / total controls evaluated</i>."
            " When the customer has assigned the framework's built-in "
            "Azure Policy initiative, this report incorporates Microsoft's "
            "authoritative per-control compliance evaluation alongside "
            "CloudGuardIQ's native configuration checks."
        )

        meta_rows = [
            ["Report type", "Automated compliance readiness (informational)"],
            ["Customer", customer_name or "—"],
            ["Subscription in scope", subscription_id],
            ["Cloud providers", provider_labels],
            ["Framework", fw.label],
            ["Controls evaluated", str(score_row.controls_total)],
            ["Data sources",
             "Provider configuration APIs; Azure Policy Regulatory "
             "Compliance; optional Defender for Cloud posture"],
            ["Generated at", generated_at],
            ["Generated by", generated_by or "Automated scheduler"],
            ["Report ID", report_id or "—"],
        ]
        meta_table = Table(meta_rows, colWidths=[1.9 * inch, 4.6 * inch])
        meta_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                     [colors.white, colors.HexColor("#f8fafc")]),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )

        return [
            Paragraph("Scope & Methodology", styles["SectionHeader"]),
            Paragraph("<b>Purpose</b>", styles["BodyText"]),
            Paragraph(purpose, styles["BodyText"]),
            Spacer(1, 0.15 * inch),
            Paragraph("<b>Coverage and Not-Assessed controls</b>", styles["BodyText"]),
            Paragraph(coverage, styles["BodyText"]),
            Spacer(1, 0.15 * inch),
            Paragraph("<b>Methodology</b>", styles["BodyText"]),
            Paragraph(methodology, styles["BodyText"]),
            Spacer(1, 0.25 * inch),
            meta_table,
        ]

    def _cover_page(
        self,
        fw: FrameworkDef,
        score_row: FrameworkScore,
        customer_name: str,
        subscription_id: str,
    ) -> list:
        styles = self._styles
        story: list = [
            Spacer(1, 1.5 * inch),
            Paragraph(self._product_name, styles["CoverSubtitle"]),
            Paragraph("Compliance Readiness Report", styles["CoverTitle"]),
            Paragraph(fw.label, styles["CoverSubtitle"]),
            Spacer(1, 0.6 * inch),
            Paragraph(f"<b>{score_row.score}%</b>", styles["ScoreBadge"]),
            Paragraph("Automated readiness score", styles["CoverSubtitle"]),
            Spacer(1, 0.4 * inch),
            Paragraph(
                "<i>Informational readiness report &mdash; not an audit or "
                "certification. Coverage is limited to controls that can be "
                "evaluated automatically from cloud configuration. See the "
                "Scope &amp; Methodology section for details.</i>",
                styles["Disclaimer"],
            ),
            Spacer(1, 0.4 * inch),
        ]
        meta_rows = [
            ["Customer", customer_name or "—"],
            ["Subscription", subscription_id],
            ["Framework", fw.label],
            ["Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
        ]
        table = Table(meta_rows, colWidths=[1.5 * inch, 4.5 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 11),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                     [colors.white, colors.HexColor("#f8fafc")]),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(table)
        return story

    def _executive_summary(
        self,
        fw: FrameworkDef,
        score_row: FrameworkScore,
        relevant: list[FindingResult],
    ) -> list:
        styles = self._styles
        sb = score_row.severity_breakdown
        critical = [f for f in relevant if f.severity == Severity.CRITICAL]
        top3 = relevant[:3]
        body = (
            f"Of the <b>{score_row.controls_total}</b> {fw.short_label} controls "
            f"that {self._product_name} can evaluate automatically from cloud "
            f"configuration, <b>{score_row.controls_passed}</b> pass and "
            f"<b>{score_row.controls_failed}</b> have one or more open findings. "
            f"The current automated readiness score is <b>{score_row.score}%</b> "
            f"with <b>{score_row.open_findings}</b> open findings "
            f"(critical: {sb.critical}, high: {sb.high}, "
            f"medium: {sb.medium}, low: {sb.low}). Controls that require "
            f"procedural, policy, or human evidence are out of scope for this "
            f"automated assessment and should be reviewed separately."
        )
        story: list = [
            Paragraph("Executive Summary", styles["SectionHeader"]),
            Paragraph(body, styles["BodyText"]),
            Spacer(1, 0.25 * inch),
            Paragraph(f"<b>Critical issues:</b> {len(critical)}", styles["BodyText"]),
            Spacer(1, 0.15 * inch),
            Paragraph("<b>Top 3 recommendations</b>", styles["BodyText"]),
        ]
        if not top3:
            story.append(
                Paragraph("No open findings for this framework.", styles["BodyText"])
            )
            return story
        for idx, f in enumerate(top3, start=1):
            story.append(
                Paragraph(
                    f"{idx}. <b>{self._severity_label(f.severity)}</b> — "
                    f"{self._safe(self._rule_label(f))}: "
                    f"{self._safe(f.description) or 'Address this finding to improve posture.'}",
                    styles["BodyText"],
                )
            )
        return story

    def _score_breakdown(
        self,
        fw: FrameworkDef,
        score_row: FrameworkScore,
        relevant: list[FindingResult],
    ) -> list:
        styles = self._styles
        # Track distinct failing control ids and total open findings per
        # category so the two columns aren't duplicates of each other.
        category_controls: dict[str, set[str]] = {}
        category_findings: dict[str, int] = {}
        for f in relevant:
            control_id = self._first_control_id(f, fw)
            if not control_id:
                continue
            category = _category_for(fw.id, control_id)
            category_controls.setdefault(category, set()).add(control_id)
            category_findings[category] = category_findings.get(category, 0) + 1
        rows = [["Category", "Failing controls", "Open findings"]]
        if category_controls:
            for cat in sorted(category_controls):
                rows.append(
                    [
                        _category_label(fw.id, cat),
                        str(len(category_controls[cat])),
                        str(category_findings[cat]),
                    ]
                )
        else:
            rows.append(["—", "0", "0"])
        table = Table(rows, colWidths=[4.0 * inch, 1.25 * inch, 1.25 * inch])
        table.setStyle(self._header_table_style())
        return [
            Paragraph("Score Breakdown", styles["SectionHeader"]),
            Paragraph(
                f"Failing controls grouped by {fw.short_label} category. "
                f"Passing controls are omitted for brevity.",
                styles["BodyText"],
            ),
            Spacer(1, 0.2 * inch),
            table,
        ]

    def _critical_findings(self, top: list[FindingResult]) -> list:
        styles = self._styles
        story: list = [Paragraph("Critical Findings", styles["SectionHeader"])]
        if not top:
            story.append(
                Paragraph("No open findings to report.", styles["BodyText"])
            )
            return story
        for f in top:
            snap = f.resource_snapshot
            resource = (
                f"{snap.resource_name} ({snap.resource_type})"
                if snap
                else self._safe(f.rule_name) or f.rule_id
            )
            cost = f"${f.waste_monthly_usd:,.2f}/mo" if f.waste_monthly_usd else "—"
            data = [
                ["Resource", resource],
                ["Finding", self._safe(self._rule_label(f))],
                ["Severity", self._severity_label(f.severity)],
                ["Description", self._safe(f.description)],
                ["Cost impact", cost],
                [
                    "Priority score",
                    f"{f.priority_score:.1f}" if f.priority_score else "—",
                ],
            ]
            table = Table(data, colWidths=[1.25 * inch, 5.0 * inch])
            table.setStyle(
                TableStyle(
                    [
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 10),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        (
                            "BACKGROUND",
                            (0, 2),
                            (1, 2),
                            _SEVERITY_COLOR.get(f.severity, colors.grey),
                        ),
                        ("TEXTCOLOR", (0, 2), (1, 2), colors.white),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                    ]
                )
            )
            story.append(table)
            story.append(Spacer(1, 0.18 * inch))
        return story

    def _controls_list(
        self,
        fw: FrameworkDef,
        score_row: FrameworkScore,
        relevant: list[FindingResult],
    ) -> list:
        styles = self._styles
        failing: dict[str, int] = {}
        for f in relevant:
            cid = self._first_control_id(f, fw)
            if cid:
                failing[cid] = failing.get(cid, 0) + 1
        rows = [["Control ID", "Status", "Open findings"]]
        if failing:
            for cid in sorted(failing.keys()):
                rows.append([cid, "FAIL", str(failing[cid])])
        passing_count = max(
            score_row.controls_total - len(failing),
            0,
        )
        if passing_count:
            rows.append(
                [
                    f"+ {passing_count} other controls",
                    "PASS",
                    "0",
                ]
            )
        table = Table(rows, colWidths=[3.0 * inch, 1.5 * inch, 2.0 * inch])
        table.setStyle(self._header_table_style())
        return [
            Paragraph("Compliance Controls", styles["SectionHeader"]),
            Paragraph(
                f"All {fw.short_label} controls CloudGuardIQ evaluates, with "
                "current pass/fail status.",
                styles["BodyText"],
            ),
            Spacer(1, 0.2 * inch),
            table,
        ]

    def _remediation_roadmap(self, relevant: list[FindingResult]) -> list:
        styles = self._styles
        story: list = [
            Paragraph("Remediation Roadmap", styles["SectionHeader"]),
            Paragraph(
                "Findings ordered by priority. Address the top items first "
                "for the largest reduction in risk and cost.",
                styles["BodyText"],
            ),
            Spacer(1, 0.2 * inch),
        ]
        rows = [["#", "Severity", "Rule", "Resource", "Waste/mo"]]
        for idx, f in enumerate(relevant[:25], start=1):
            snap = f.resource_snapshot
            resource = snap.resource_name if snap else "—"
            waste = (
                f"${f.waste_monthly_usd:,.0f}" if f.waste_monthly_usd else "—"
            )
            rows.append(
                [
                    str(idx),
                    self._severity_label(f.severity),
                    self._safe(self._rule_label(f))[:60],
                    self._safe(resource)[:32],
                    waste,
                ]
            )
        if len(rows) == 1:
            rows.append(["—", "—", "Nothing to remediate", "—", "—"])
        table = Table(
            rows,
            colWidths=[0.4 * inch, 0.9 * inch, 3.0 * inch, 1.9 * inch, 0.9 * inch],
        )
        table.setStyle(self._header_table_style())
        story.append(table)
        return story

    def _appendix(self, relevant: list[FindingResult]) -> list:
        styles = self._styles
        story: list = [
            Paragraph("Appendix — Finding Details", styles["SectionHeader"]),
            Paragraph(
                "Technical detail for every open finding included in this report.",
                styles["BodyText"],
            ),
            Spacer(1, 0.2 * inch),
        ]
        if not relevant:
            story.append(Paragraph("No open findings.", styles["BodyText"]))
            return story
        for f in relevant:
            snap = f.resource_snapshot
            resource_id = snap.id if snap else "—"
            story.append(
                Paragraph(
                    f"<b>{f.rule_id}</b> · {self._severity_label(f.severity)} · "
                    f"{self._safe(self._rule_label(f))}",
                    styles["BodyText"],
                )
            )
            story.append(
                Paragraph(
                    f"Resource: <font name='Courier'>{self._safe(resource_id)}</font>",
                    styles["BodyText"],
                )
            )
            if f.description:
                story.append(Paragraph(self._safe(f.description), styles["BodyText"]))
            if f.compliance_frameworks:
                story.append(
                    Paragraph(
                        "Frameworks: " + ", ".join(f.compliance_frameworks),
                        styles["BodyText"],
                    )
                )
            story.append(Spacer(1, 0.12 * inch))
        return story

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_framework(framework: str) -> str:
        token = (framework or "").strip().upper().replace("-", "_").replace(" ", "_")
        aliases = {
            "CIS": "CIS_AZURE",
            "CIS_AZURE": "CIS_AZURE",
            "NIST": "NIST_800_53",
            "NIST_800_53": "NIST_800_53",
            "ISO": "ISO_27001",
            "ISO_27001": "ISO_27001",
            "PCI": "PCI_DSS",
            "PCI_DSS": "PCI_DSS",
            "SOC2": "SOC2",
            "SOC_2": "SOC2",
            "HIPAA": "HIPAA",
        }
        return aliases.get(token, token)

    @staticmethod
    def _is_open(f: FindingResult) -> bool:
        status = getattr(f, "status", None) or FindingStatus.OPEN
        return status == FindingStatus.OPEN

    @staticmethod
    def _has_framework_tag(f: FindingResult, fw: FrameworkDef) -> bool:
        for tag in f.compliance_frameworks or []:
            classified = _classify(tag)
            if classified and classified[0] == fw.id:
                return True
        return False

    @staticmethod
    def _first_control_id(f: FindingResult, fw: FrameworkDef) -> str:
        for tag in f.compliance_frameworks or []:
            classified = _classify(tag)
            if classified and classified[0] == fw.id:
                return classified[1]
        return ""

    @staticmethod
    def _finding_sort_key(f: FindingResult) -> tuple[int, float]:
        return (
            _SEVERITY_ORDER.get(f.severity, 99),
            -float(f.priority_score or 0.0),
        )

    @staticmethod
    def _severity_label(sev: Severity) -> str:
        return sev.value.upper() if hasattr(sev, "value") else str(sev)

    @staticmethod
    def _rule_label(f: FindingResult) -> str:
        return f.rule_name or f.rule_id or ""

    @staticmethod
    def _safe(value: str | None) -> str:
        if not value:
            return ""
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    @staticmethod
    def _header_table_style() -> TableStyle:
        return TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
