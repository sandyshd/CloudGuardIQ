# CloudGuardIQ - Multi-Cloud Onboarding Design (Executable Spec)

Status: Proposed for implementation
Owner: Platform + API team
Last updated: 2026-05-19
Related roadmap: [saas-phased-plan.md](./saas-phased-plan.md) (Phase 6)

---

## 1) Scope and guardrails

This document defines the exact onboarding design for linking customer
Azure, AWS, and GCP environments into CloudGuardIQ.

Hard requirements:

- Adapter modules are the only layer that talks to cloud SDKs/APIs.
- Policy rules evaluate `ResourceSnapshot` only.
- No static long-lived cloud credentials stored in Cosmos.
- All secrets and credential materials are referenced from Azure Key Vault.
- Every onboarding action is tenant-scoped (`tenant_id` from JWT `tid`) and audited.

---

## 2) High-level flow

Unified onboarding flow for all providers:

1. Create onboarding session.
2. Generate provider artifacts (consent URL, role template, trust policy).
3. Customer admin applies trust/permissions in cloud provider.
4. Verify trust + least-privilege permissions + discovery.
5. Connect selected scopes and activate scans.

State machine:

- `initiated`
- `artifacts_generated`
- `consent_pending`
- `trust_pending`
- `verifying`
- `action_required`
- `verified`
- `connected`
- `failed`
- `disconnected`

Transition rules:

- `verify` is the only path to `verified`.
- `connect` allowed only from `verified`.
- Any auth or RBAC/IAM deficiency moves to `action_required` with structured remediation.

---

## 3) API contract

Base path: `/v1`

### 3.1 Create session

`POST /onboarding/sessions`

Request body:

```json
{
  "provider": "AZURE",
  "display_name": "Contoso Production",
  "target_scope": {
    "tenant_id": "11111111-2222-3333-4444-555555555555"
  }
}
```

Response `201`:

```json
{
  "session_id": "c7d9a15d0b8d42c6a2f1df698a9d55ee",
  "provider": "AZURE",
  "status": "initiated",
  "next_actions": [
    "generate_artifacts"
  ],
  "created_at": "2026-05-19T09:12:41Z"
}
```

### 3.2 Generate artifacts

`POST /onboarding/sessions/{session_id}/generate-artifacts`

Response `200` (provider-specific payload):

```json
{
  "session_id": "c7d9a15d0b8d42c6a2f1df698a9d55ee",
  "provider": "AZURE",
  "status": "consent_pending",
  "artifacts": {
    "consent_url": "https://login.microsoftonline.com/<tenant>/adminconsent?...",
    "template_uri": "https://raw.githubusercontent.com/.../azure-onboarding.json",
    "deploy_url": "https://portal.azure.com/#create/Microsoft.Template/uri/..."
  }
}
```

### 3.3 Verify onboarding

`POST /onboarding/sessions/{session_id}/verify`

Response `200` (`verified`):

```json
{
  "session_id": "c7d9a15d0b8d42c6a2f1df698a9d55ee",
  "provider": "AZURE",
  "status": "verified",
  "verification_checks": [
    {
      "check": "token_exchange",
      "status": "pass"
    },
    {
      "check": "permission_probe",
      "status": "pass"
    },
    {
      "check": "scope_discovery",
      "status": "pass"
    }
  ],
  "discovered_scopes": [
    {
      "id": "00000000-0000-0000-0000-000000000001",
      "display_name": "Prod Subscription",
      "kind": "subscription"
    }
  ]
}
```

Response `400` (`action_required`):

```json
{
  "error_code": "reader_role_required",
  "provider": "AZURE",
  "step": "permission_probe",
  "message": "CloudGuardIQ has consent but missing Reader role at target scope.",
  "remediation": [
    "Grant Reader role using deploy_url.",
    "Wait RBAC propagation and retry verify."
  ],
  "correlation_id": "4ef0ddcb9f7f4d03b8b3c5a50cb25232"
}
```

### 3.4 Connect verified scopes

`POST /onboarding/sessions/{session_id}/connect`

Request body:

```json
{
  "scope_ids": [
    "00000000-0000-0000-0000-000000000001"
  ]
}
```

Response `201`:

```json
{
  "connection_id": "fca354f2ce59468fa3d8a847f84e1b53",
  "provider": "AZURE",
  "status": "connected",
  "linked_scopes": [
    "00000000-0000-0000-0000-000000000001"
  ]
}
```

### 3.5 Connection lifecycle endpoints

- `GET /cloud-connections`
- `GET /cloud-connections/{connection_id}`
- `POST /cloud-connections/{connection_id}/refresh`
- `DELETE /cloud-connections/{connection_id}`

Disconnect behavior:

- Mark connection `disconnected`.
- Stop scheduler fan-out for that connection.
- Remove cached tokens and invalidate runtime credential handles.
- Preserve historical findings per retention policy.

---

## 4) Pydantic models (wire and storage)

```python
from pydantic import BaseModel, Field
from typing import Literal


CloudProvider = Literal["AZURE", "AWS", "GCP"]
SessionStatus = Literal[
    "initiated",
    "artifacts_generated",
    "consent_pending",
    "trust_pending",
    "verifying",
    "action_required",
    "verified",
    "connected",
    "failed",
    "disconnected",
]


class OnboardingTargetScope(BaseModel):
    tenant_id: str = ""      # Azure
    account_id: str = ""     # AWS
    project_id: str = ""     # GCP
    organization_id: str = ""  # GCP org onboarding


class OnboardingSessionCreateRequest(BaseModel):
    provider: CloudProvider
    display_name: str = Field(default="", max_length=120)
    target_scope: OnboardingTargetScope


class VerificationCheck(BaseModel):
    check: Literal["token_exchange", "permission_probe", "scope_discovery"]
    status: Literal["pass", "fail", "warning"]
    detail: str = ""


class DiscoveredScope(BaseModel):
    id: str
    display_name: str = ""
    kind: str


class OnboardingSessionResponse(BaseModel):
    session_id: str
    provider: CloudProvider
    status: SessionStatus
    verification_checks: list[VerificationCheck] = []
    discovered_scopes: list[DiscoveredScope] = []
```

Notes:

- These are transport/domain models; cloud SDK objects never leave adapters.
- All models remain JSON-safe and provider-neutral where possible.

---

## 5) Cosmos DB schema

### 5.1 `onboarding_sessions` container

Partition key: `/tenant_id`

Document shape:

```json
{
  "id": "c7d9a15d0b8d42c6a2f1df698a9d55ee",
  "tenant_id": "home-tenant-guid",
  "provider": "AZURE",
  "target_scope": {
    "tenant_id": "customer-tenant-guid"
  },
  "status": "action_required",
  "artifact_payload": {
    "consent_url": "...",
    "deploy_url": "..."
  },
  "verification_results": [
    {"check": "token_exchange", "status": "pass"}
  ],
  "discovered_scopes": [],
  "created_by": "aad-object-id",
  "correlation_id": "trace-guid",
  "error_code": "reader_role_required",
  "error_message": "Reader role missing",
  "created_at": "2026-05-19T09:12:41Z",
  "updated_at": "2026-05-19T09:14:10Z",
  "expires_at": "2026-06-18T09:12:41Z"
}
```

TTL: 30 days

### 5.2 `cloud_connections` container

Partition key: `/tenant_id`

Fields:

- `id` (`connection_id`)
- `tenant_id`
- `provider`
- `display_name`
- `linked_scopes`
- `auth_mode` (`azure_sp_consent`, `aws_assume_role`, `gcp_wif`)
- `status` (`active`, `degraded`, `disconnected`)
- `last_verified_at`, `last_scan_at`, `created_at`, `updated_at`

### 5.3 `credential_refs` container

Partition key: `/tenant_id`

Fields:

- `id`
- `tenant_id`
- `connection_id`
- `provider`
- `secret_ref` (Key Vault URI only)
- `token_metadata` (`expires_at`, `last_refresh_at`, `issuer`)
- `rotation_policy`

Never store raw access tokens or private keys in Cosmos documents.

### 5.4 `audit_events` container

Partition key: `/tenant_id`

Fields:

- `id`
- `tenant_id`
- `actor_id`
- `action`
- `provider`
- `resource_id`
- `result`
- `request_id`
- `timestamp`
- `details` (sanitized)

---

## 6) Token and credential handling

### 6.1 Frontdoor identity (CloudGuardIQ user)

- OIDC/OAuth with Entra ID.
- Backend validates `iss`, `aud`, `exp`, and `tid`.
- `tid` is required and used for all repository filters.

### 6.2 Azure onboarding auth

- Multi-tenant Entra app admin consent in customer tenant.
- Prefer certificate credentials or workload identity federation.
- Use per-tenant token acquisition during discovery and scans.
- Cache short-lived tokens in memory only.

### 6.3 AWS onboarding auth

- Customer creates cross-account role with trust to CloudGuardIQ AWS principal.
- Trust policy requires per-tenant `ExternalId`.
- Runtime uses `sts:AssumeRole` with short session duration.

### 6.4 GCP onboarding auth

- Use Workload Identity Federation and service account impersonation.
- No static JSON service account keys.
- Runtime uses short-lived access tokens from STS/iamcredentials APIs.

### 6.5 Callback integrity

- Signed `state` and nonce for callback endpoints.
- Callback records consent/trust status only; does not auto-connect.
- Final `connect` remains explicit and idempotent.

---

## 7) Verification contract (provider-specific)

`POST /onboarding/sessions/{session_id}/verify` runs these checks:

1. Token exchange:
   - Azure: token for customer tenant succeeds.
   - AWS: `AssumeRole` succeeds.
   - GCP: WIF + SA impersonation succeeds.
2. Permission probe:
   - Azure: subscription list/read probes.
   - AWS: `GetCallerIdentity` + selected read probes.
   - GCP: project/folder/org read probe.
3. Scope discovery:
   - Azure: subscriptions.
   - AWS: account + enabled regions (and optional org accounts).
   - GCP: projects/folders under granted scope.

Failure mapping must return structured remediation payloads, not raw SDK errors.

---

## 8) Least-privilege templates

### 8.1 Azure

Minimum role set:

- `Reader`
- `Security Reader` (for security posture sources)
- `Cost Management Reader` (for FinOps cost visibility)

ARM/Bicep template inputs:

- `cloudguardiqPrincipalObjectId`
- `scopeType` (`managementGroup` or `subscription`)
- `scopeId`

### 8.2 AWS

Trust policy (example):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::<cloudguardiq-account-id>:role/cloudguardiq-control-plane"},
      "Action": "sts:AssumeRole",
      "Condition": {"StringEquals": {"sts:ExternalId": "<tenant-external-id>"}}
    }
  ]
}
```

Permission policy baseline:

- Inventory read (EC2, S3, RDS, IAM metadata)
- Security read (Security Hub, GuardDuty, Config)
- Cost read (`ce:GetCostAndUsage`, `ce:GetDimensionValues`, `ce:GetRightsizingRecommendation`)

### 8.3 GCP

Baseline IAM grants:

- Viewer-level inventory read on target scope
- Security Command Center findings viewer (if SCC integrated)
- Billing/read-only permissions for FinOps metrics
- Recommender read permissions

WIF binding grants principalSet access to a service account used for impersonation.

---

## 9) Error model

All onboarding endpoints use a shared error shape:

```json
{
  "error_code": "consent_required",
  "provider": "AZURE",
  "step": "consent",
  "message": "Admin consent is required before verification.",
  "remediation": [
    "Open consent_url as customer tenant admin.",
    "Retry verify after consent callback completes."
  ],
  "docs_url": "https://docs.cloudguardiq.com/onboarding/azure",
  "correlation_id": "4ef0ddcb9f7f4d03b8b3c5a50cb25232"
}
```

Canonical error codes:

- `consent_required`
- `trust_not_configured`
- `role_missing`
- `external_id_mismatch`
- `wif_binding_missing`
- `token_exchange_failed`
- `discovery_failed`
- `provider_not_supported`

---

## 10) Implementation slicing

### Slice A (Azure hardening + unified session API)

- Introduce unified onboarding session endpoints under `/v1/onboarding/sessions`.
- Keep existing Azure flow, migrate to new response envelope.
- Add standardized error model and audit events.

### Slice B (AWS onboarding)

- Add AWS provider strategy + adapter integration.
- Add role template generation and verify probes.

### Slice C (GCP onboarding)

- Add GCP WIF onboarding strategy + adapter integration.
- Add verify probes and least-privilege templates.

### Slice D (operations hardening)

- Scheduled re-verification.
- Connection health dashboard fields.
- Automated drift alerts when role/trust breaks.

---

## 11) Acceptance criteria

- Customer can link Azure, AWS, and GCP without sharing passwords or long-lived keys.
- Verify endpoint always returns actionable remediation on failure.
- All cloud access uses delegated trust and short-lived credentials.
- Every onboarding state transition is tenant-scoped and auditable.
- Policy engine consumes only normalized `ResourceSnapshot` with valid `data_tier`.
