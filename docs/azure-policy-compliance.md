# Azure Policy Regulatory Compliance Adapter

## Why read from Azure Policy instead of duplicating Microsoft's catalogue

Microsoft maintains built-in **Regulatory Compliance** initiatives (policy set
definitions) for CIS, NIST 800-53, ISO 27001, PCI DSS, SOC 2, and HIPAA. Each
initiative contains hundreds of individual policy definitions, each already
mapped by Microsoft to specific framework controls. Microsoft evaluates these
policies continuously and exposes the per-resource compliance state through the
**Policy Insights** API.

CloudGuardIQ reads this authoritative compliance state directly rather than
re-implementing Microsoft's control catalogue. This means:

- **No catalogue drift.** When Microsoft updates a control mapping or adds a
  policy, CloudGuardIQ picks it up automatically &mdash; we do not have to
  mirror thousands of control-to-policy mappings.
- **Authoritative source.** Auditors recognise Microsoft's Regulatory
  Compliance evaluation. We surface it alongside our own native configuration
  checks rather than competing with it.
- **Cheap and read-only.** Querying policy state requires only **Reader**
  (plus the built-in `Policy Insights Data Writer`-free read path). No agent,
  no Defender for Cloud licence, no write access.

CloudGuardIQ's native scanner rules remain the primary engine. Policy-sourced
findings are merged in as an additional, authoritative tier
(`TIER1_NATIVE`) and routed through the same scorecard via their
`compliance_frameworks` tags (e.g. `CIS_AZURE:3.1`).

## Which initiatives are queried

The adapter queries the built-in initiatives listed in
`FRAMEWORK_INITIATIVES` in
[cloudguardiq/adapters/azure/azure_policy_compliance_adapter.py](../cloudguardiq/adapters/azure/azure_policy_compliance_adapter.py):

| Framework      | Built-in initiative (policy set definition) |
| -------------- | ------------------------------------------- |
| CIS_AZURE      | CIS Microsoft Azure Foundations Benchmark   |
| NIST_800_53    | NIST SP 800-53 Rev. 5                        |
| ISO_27001      | ISO 27001:2013                              |
| PCI_DSS        | PCI DSS v4                                   |
| SOC2           | SOC 2 Type 2                                |
| HIPAA          | HIPAA HITRUST 9.2                           |

Only initiatives that are **assigned** in the customer subscription are
queried; unassigned initiatives are skipped (see
`_list_assigned_initiatives`).

### How to add a framework

1. Find the built-in policy set definition GUID for the framework
   (`az policy set-definition list --management-group <builtin>` or the portal).
2. Add an entry to `FRAMEWORK_INITIATIVES` keyed by the framework id and add the
   reverse mapping in `_INITIATIVE_TO_FRAMEWORK`.
3. Ensure the framework id matches an entry in
   `cloudguardiq/compliance/scorecard.py` `FRAMEWORKS` so findings route to a
   scorecard row.

## Quarterly GUID review

Microsoft occasionally republishes initiatives under new GUIDs (e.g. moving
from CIS v1.4 to a newer benchmark). Review `FRAMEWORK_INITIATIVES` **quarterly**
against the current built-in policy set definitions and update any GUIDs that
have been superseded. A stale GUID degrades gracefully (the initiative simply
appears unassigned and is skipped), but the corresponding Policy-sourced
findings will silently stop appearing, so the review is important.

## Control-id resolution and caching

Policy state rows reference a `policyDefinitionReferenceId` / group name rather
than a human control id. The adapter resolves these to framework control ids by
reading the initiative's `policyDefinitionGroups` via
`PolicyClient.policy_set_definitions.get_built_in`, and caches the mapping in
the system container for **30 days** (`_CONTROL_MAP_TTL_DAYS`) to avoid repeated
control-plane calls. See `get_policy_control_map` /
`save_policy_control_map` in
[cloudguardiq/core/database.py](../cloudguardiq/core/database.py).

## Customer-facing implication

For the customer, enabling this data source is a **one-time, free** action:
assign the framework's built-in Azure Policy initiative to the subscription (or
management group). It requires no extra licence and is compatible with a
**Reader** role assignment. Once assigned, the readiness report incorporates
Microsoft's authoritative per-control compliance evaluation alongside
CloudGuardIQ's native configuration checks.

## Capability detection

`CapabilityDetector` probes for assigned initiatives and sets
`policy_compliance_available` on `CapabilityFlags`. The probe is best-effort and
degrades to `False` on any error, so a missing assignment or restricted
permissions never breaks a scan.
