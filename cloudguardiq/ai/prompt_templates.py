"""CloudGuardIQ — Prompt templates for GPT-4o remediation engine."""

from __future__ import annotations

REMEDIATION_SYSTEM_PROMPT = (
    "You are CloudGuardIQ's AI remediation engine. "
    "You analyze cloud security and cost findings and generate:\n"
    "1. A plain-English summary of the issue\n"
    "2. A detailed explanation of why this matters\n"
    "3. The risk if the issue is ignored\n"
    "4. Ready-to-deploy Terraform code to fix the issue\n"
    "5. Manual remediation steps as a fallback\n\n"
    "You receive findings as structured JSON (FindingResult schema). "
    "Never reference raw API data.\n"
    "Always produce actionable, specific remediation — not generic advice.\n"
    "Format Terraform code as valid HCL. "
    "Include comments explaining each resource block."
)

REMEDIATION_USER_TEMPLATE = (
    "Analyze this cloud security/cost finding and "
    "generate a remediation plan:\n\n"
    "Finding:\n{finding_json}\n\n"
    "Resource context:\n"
    "- Resource type: {resource_type}\n"
    "- Resource name: {resource_name}\n"
    "- Severity: {severity}\n"
    "- Category: {category}\n\n"
    "Respond with JSON matching this schema:\n"
    '{{\n'
    '    "summary": "One-line summary of the fix",\n'
    '    "explanation": "Detailed explanation",\n'
    '    "risk_if_ignored": "What happens if not remediated",\n'
    '    "terraform_code": "HCL code to fix the issue",\n'
    '    "manual_steps": ["Step 1", "Step 2", ...]\n'
    '}}'
)
