# CloudGuardIQ — Phased Plan to become a real multi-tenant SaaS

> Status: Proposal / planning document. No code has been changed yet.
>
> Scope: Move from the current single-subscription, single-tenant deployment
> (where `AZURE_SUBSCRIPTION_ID` is baked in at Terraform time) to a
> multi-tenant, multi-subscription, tier-gated SaaS where customers manage
> their own Azure subscriptions from the Settings page.

---

## Table of Contents

- [Phase 0 — Pre-work](#phase-0--pre-work-half-day)
- [Phase 1 — Tenant isolation (foundation)](#phase-1--tenant-isolation-foundation)
- [Phase 2 — User-managed subscriptions (single-tenant)](#phase-2--user-managed-subscriptions-single-tenant)
- [Phase 3 — Cross-tenant support (true SaaS onboarding)](#phase-3--cross-tenant-support-true-saas-onboarding)
- [Phase 4 — Scale & operational hardening](#phase-4--scale--operational-hardening)
- [Phase 5 — Nice-to-haves (backlog)](#phase-5--nice-to-haves-backlog)
- [Phase 6 — Multi-cloud (AWS + GCP)](#phase-6--multi-cloud-aws--gcp)
- [Cross-phase definition of done](#cross-phase-definition-of-done-every-phase)
- [Suggested sequencing](#suggested-sequencing)

---

## Phase 0 — Pre-work (half day)

Goal: lock down assumptions before touching code.

- [x] Decide **tenant identity source**: Azure AD `tid` claim from the user's
      JWT (recommended — already validated in `cloudguardiq/api/auth.py`).
- [x] Decide **per-tier subscription caps**: FREE=1, PRO=10, ENTERPRISE=unlimited
      (or `-1`).
- [x] Decide **downgrade policy** (Pro -> Free with 7 subs connected): auto-disable
      extras, keep oldest N active; grace period = 0.
- [x] Decide **cross-tenant auth strategy** for Phase 3: multi-tenant app +
      client certificate in Key Vault (recommended over Azure Lighthouse for
      simpler onboarding).
- [x] Captured in [`docs/saas-decisions.md`](./saas-decisions.md).

**Exit criteria:** written decisions, no code changes. ✅ Completed 2026-04-29 — see [`saas-decisions.md`](./saas-decisions.md).

---

## Phase 1 — Tenant isolation (foundation)

**Goal:** every row in Cosmos is scoped by `tenant_id`; no cross-tenant reads
possible.

This phase changes nothing visible to users but is the **non-negotiable**
prerequisite for everything else.

### 1.1 Models

- Add `tenant_id: str` to `ResourceSnapshot`, `FindingResult`,
  `RemediationCard`, scan-result docs in `cloudguardiq/core/models.py`.
- Update `frontend/src/types/index.ts` mirrors.

### 1.2 Auth -> tenant

- Extend `TokenPayload` in `cloudguardiq/api/auth.py` with `tid` and `oid`.
- Add `get_tenant_id(user: TokenPayload) -> str` helper; reject request with
  401 if `tid` missing.

### 1.3 Cosmos repository

- Every read/write in `cloudguardiq/core/database.py` takes `tenant_id` and
  filters by it in queries.
- Partition-key strategy: keep current PKs (e.g. `/subscription_id`), add
  mandatory `tenant_id` filter in every `WHERE` clause. (Do **not**
  repartition — too disruptive; filter-by-tenant is enough for now.)
- Remove `_resolve_subscription_id` env fallback in
  `cloudguardiq/api/main.py`.

### 1.4 Billing already tenant-scoped

- `BillingRepository` already keys on `tenant_id`
  (`cloudguardiq/billing/repository.py`) — verify `_tenant_id(user)` in
  `cloudguardiq/api/billing.py` uses `tid` not `sub`.

### 1.5 Tests

- New: `tests/core/test_tenant_isolation.py` — two tenants, verify tenant B
  cannot read tenant A's findings even with guessed IDs.
- Update existing scan/findings tests to pass a `tenant_id`.

### 1.6 Backfill migration

- One-off script `scripts/backfill_tenant_id.py` that stamps all existing
  docs with a default `tenant_id` from `CLOUDGUARDIQ_AZURE_TENANT_ID` env
  var, run once during deploy.

**Exit criteria:** all 324+ tests pass; `ruff` + `mypy` green; deployed to
dev; verified manually that two users from two different tenants (or spoofed
`tid`) see disjoint data.

**Status:** ⚠ Partially complete (2026-04-29). Code & tests landed on
`development` (375/375 tests pass, `ruff` clean). Pre-existing `mypy`
findings in unrelated files are out of scope. The
`_resolve_subscription_id` env fallback removal is **deferred to Phase 2**
because the frontend does not yet pass `subscription_id` from a global
selector — removing it now would break Dashboard / Findings reads. Manual
two-tenant smoke test pending Phase 2 deploy.

---

## Phase 2 — User-managed subscriptions (single-tenant)

**Goal:** the Settings UI becomes functional for customers inside **your own
Entra tenant**. Tier caps enforced. No `AZURE_SUBSCRIPTION_ID` env var.

### 2.1 Data layer

- New Cosmos container `subscriptions`, PK `/tenant_id`, doc shape:

  ```json
  {
    "id": "tid:subid",
    "tenant_id": "...",
    "subscription_id": "a0e75be9-...",
    "display_name": "Prod eastus",
    "state": "Enabled",
    "added_at": "...",
    "last_scan_at": "..."
  }
  ```

- New module `cloudguardiq/subscriptions/repository.py` mirroring
  `BillingRepository` (Cosmos + in-memory fallback).
- Add `cosmos_container_subscriptions: str = "subscriptions"` to `Settings`.

### 2.2 Backend API — replace env-driven `/subscriptions`

New router `cloudguardiq/api/subscriptions.py`:

| Method | Path                        | Behavior                                                                                                                                                                                              |
| ------ | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/subscriptions`            | List tenant's subs from repo (no env fallback)                                                                                                                                                        |
| POST   | `/subscriptions`            | Body `{subscription_id, display_name?}`; validate GUID; check tier cap; call `SubscriptionClient.get()` with caller's delegated token to prove *user* has rights; then check MI has Reader; upsert |
| PATCH  | `/subscriptions/{id}`       | Rename, enable/disable                                                                                                                                                                                |
| DELETE | `/subscriptions/{id}`       | Unlink                                                                                                                                                                                                |

Wire in `lifespan` in `cloudguardiq/api/main.py` like
`billing_module.configure()`.

### 2.3 Scan paths

- `/scan`, `/scan/trigger`, `/findings*` require `subscription_id`
  query/body; reject if not owned by the tenant
  (`403 subscription_not_linked`).
- `cloudguardiq/cli.py` — remove env fallback; require `--subscription-id`.

### 2.4 Tier enforcement

`cloudguardiq/billing/middleware.py`:

- Wire `subscription_counter = lambda tid: subs_repo.count(tid)` at startup.
- Add `pro_max_subscriptions=10` to `Settings`; update
  `_over_subscription_limit` to look up by tier:
  - FREE -> `free_max_subscriptions`
  - PRO  -> `pro_max_subscriptions`
  - ENTERPRISE -> no limit
- `_tenant_id(user)` must use `tid` (from Phase 1).

### 2.5 Scheduler (Function)

`function_app.py` `scan_trigger`:

- Query `subscriptions` container across all tenants where
  `state == "Enabled"`.
- For each: enqueue a Service Bus message
  `{tenant_id, subscription_id}` (do not run inline — already correct
  pattern).
- New worker function `per_subscription_scan` consumes queue;
  `AzureAdapter` gets `subscription_id` from message, not env.
- Catch per-subscription errors; log and continue.
- Remove all `os.environ.get("AZURE_SUBSCRIPTION_ID", "")` reads.

### 2.6 Frontend

- `frontend/src/api/subscriptions.ts` — add `addSubscription`,
  `removeSubscription`, `toggleSubscription`, `renameSubscription`.
- `frontend/src/components/settings/SubscriptionList.tsx`:
  - "Add subscription" form (GUID + name).
  - Remove / Enable / Disable actions per row.
  - Tier counter: "2 of 10 used (Pro)".
  - Onboarding help panel: "Grant `Reader` to app `{client_id}` on this
    subscription" (shows client_id from a new `/me` or `/config` endpoint).
- Global subscription selector (dropdown in header/sidebar) — new context
  provider; every page reads selected sub from context;
  Dashboard/Findings/FinOps/Compliance calls carry `?subscription_id=...`.
- `frontend/src/components/settings/TierSelector.tsx` — update Pro copy to
  "Up to 10 Azure subscriptions".
- Handle `402 upgrade_required` with an upgrade CTA modal.

### 2.7 Terraform (`infra/main.tf`)

- **Add** `azurerm_cosmosdb_sql_container.subscriptions` (mirror the
  `billing` block at L189).
- **Remove** `AZURE_SUBSCRIPTION_ID` env from Container App (L464-L467) and
  Function App (L618).
- **Add** `CLOUDGUARDIQ_COSMOS_CONTAINER_SUBSCRIPTIONS` env on both apps.
- **Add** `CLOUDGUARDIQ_PRO_MAX_SUBSCRIPTIONS=10` env on both apps.
- Keep existing Reader role on the deployment sub for self-scan bootstrap.
- Expose `azure_ad_client_id` in `infra/outputs.tf` (already there) —
  frontend will show it in onboarding help.

### 2.8 Env var audit (remove / keep)

| Scope                       | Var                                          | Action                                                            |
| --------------------------- | -------------------------------------------- | ----------------------------------------------------------------- |
| Container App               | `AZURE_SUBSCRIPTION_ID`                      | **Remove**                                                        |
| Function App                | `AZURE_SUBSCRIPTION_ID`                      | **Remove**                                                        |
| Local `.env.example` / README | `AZURE_SUBSCRIPTION_ID`                    | Mark "dev-only, used by CLI `--subscription-id` default"          |
| Frontend                    | none referenced                              | No change                                                         |
| New                         | `CLOUDGUARDIQ_COSMOS_CONTAINER_SUBSCRIPTIONS`| Add                                                               |
| New                         | `CLOUDGUARDIQ_PRO_MAX_SUBSCRIPTIONS`         | Add                                                               |

### 2.9 Tests

- `tests/subscriptions/test_repository.py`
- `tests/api/test_subscriptions_routes.py` (add/list/delete, 402 cap, 403
  not-owned, 403 no-access)
- `tests/billing/test_middleware.py` — Pro cap and counter wiring
- `tests/api/test_scan_routes.py` — scans require registered sub
- Update `tests/conftest.py` to seed subscription records

### 2.10 Migration

- On first deploy: lifespan hook — if a tenant has zero subs recorded but
  `AZURE_SUBSCRIPTION_ID` is still set (transitional), insert it once and
  log "migrated". Remove the hook in Phase 3.

**Exit criteria:** user can add/remove subs in UI; tier caps enforced;
scans only run for registered subs; all tests green; both Terraform env
vars gone from cloud; product works end-to-end for customers in **your**
Entra tenant.

---

## Phase 3 — Cross-tenant support (true SaaS onboarding)

**Goal:** customers in *other* Entra tenants can connect their subscriptions.

### 3.1 Azure AD app -> multi-tenant

- `infra/main.tf` `azuread_application.cloudguardiq`:
  - `sign_in_audience = "AzureADMultipleOrgs"`
  - Add API permission `https://management.azure.com/user_impersonation`
    (delegated) if not present.
- Publisher verification: required by Microsoft for non-verified
  multi-tenant apps in prod — factor in the Microsoft Partner Network step.

### 3.2 Cross-tenant credential

- Provision a **client certificate** (not secret) on the app registration
  in Terraform; store PFX in Key Vault.
- New module `cloudguardiq/auth/customer_credential.py` returning
  `ClientCertificateCredential(tenant_id=customer_tid, client_id=...,
  certificate_data=...)` for scanning *that* customer's resources.
- `AzureAdapter` constructor accepts a credential factory; scan pipeline
  builds credential per-subscription using the subscription record's
  `tenant_id`.

### 3.3 Admin consent flow

- New endpoint `GET /subscriptions/consent-url?tenant_id=...` returns
  `https://login.microsoftonline.com/{tid}/adminconsent?client_id=...&redirect_uri=...`.
- New endpoint `GET /subscriptions/consent-callback` records consent
  (create a `tenant_consents` Cosmos container).
- Frontend `SubscriptionList` onboarding:
  1. Consent as admin (opens consent URL in popup).
  2. Assign Reader to app in Azure Portal (copy-button with instructions).
  3. Add subscription.

### 3.4 Subscription add — cross-tenant verification

- On `POST /subscriptions`: use the **customer-tenant credential** to call
  `SubscriptionClient.get()`; if 403, instruct the user to grant Reader.
- Block add if consent not recorded for the sub's tenant.

### 3.5 Subscription record shape

- Add `customer_tenant_id` field (Azure tenant that owns the subscription,
  distinct from the CloudGuardIQ *user's* tenant — usually the same but not
  always).

### 3.6 Scheduler

- `per_subscription_scan` now builds per-customer-tenant credential;
  handles 401/403 gracefully (mark sub `Disabled`, notify tenant admin).

### 3.7 Tests

- `tests/auth/test_customer_credential.py` — factory picks right tenant.
- `tests/api/test_consent_flow.py`.
- Integration test with mocked multi-tenant ARM.

### 3.8 Documentation

- README section "Connecting subscriptions from another Entra tenant".

**Exit criteria:** a customer in tenant B can self-onboard, consent, assign
Reader, and start getting findings within 15 minutes.

**Status:** ✓ Implemented. Multi-tenant app registration (already in Phase 1 TF), `CustomerCredentialFactory`, `TenantConsentRepository` (`tenant_consents` Cosmos container), `/subscriptions/consent-url` & `/subscriptions/consent-callback` endpoints, `customer_tenant_id` on `SubscriptionRecord`, multi-tenant JWT validation, cross-tenant probe in `POST /subscriptions`, and per-customer-tenant credential in `function_app.scan_trigger` (with auto-disable on 401/403). All 483 tests pass; ruff clean. Pre-existing two event-loop tests in `tests/policy/test_engine.py` remain out of scope.

---

## Phase 4 — Scale & operational hardening

**Goal:** handle 100+ tenants x 10 subs without melting.

### 4.1 Scheduler fan-out & jitter

- Timer publishes one Service Bus message per sub with random
  `scheduled_enqueue_time_utc` jitter (0-300s).
- Worker concurrency tuned via Function App
  `FUNCTIONS_WORKER_PROCESS_COUNT`.

### 4.2 Per-subscription locks

- Cosmos `system` container row `scan_lock:{sub_id}` with TTL; worker skips
  if locked.

### 4.3 Rate limits

- Per-tenant API rate limit (add to `TierEnforcementMiddleware`):
  FREE=60 rpm, PRO=600 rpm, ENTERPRISE=unbounded.

### 4.4 ARM throttling

- Exponential backoff + circuit breaker in `AzureAdapter.list_resources`.

### 4.5 Observability

- Application Insights custom dimensions: `tenant_id`, `subscription_id`,
  `scan_id` on every log/metric.
- Dashboards: scans per tenant, failures per tenant, cost per tenant
  (Cosmos RU).

### 4.6 Downgrade / churn handling

- Stripe webhook `customer.subscription.deleted` -> disable subs beyond the
  new tier's cap (oldest-first preserved).
- Nightly job deletes tenants that have been FREE-with-zero-subs for 90
  days (GDPR).

**Exit criteria:** synthetic load test of 500 subs/hour completes with
<1% error rate.

---

## Phase 5 — Nice-to-haves (backlog)

- Per-subscription scan schedule override (Enterprise feature).
- Subscription groups / tags for filtering UI.
- Azure Lighthouse as an alternative onboarding path.
- Management group onboarding (one consent -> all subs under MG).
- Per-user RBAC within a tenant (admin vs. viewer).

---

## Phase 6 — Multi-cloud (AWS + GCP)

**Goal:** customers can link AWS accounts and GCP projects from the same
Settings page. Cloud-agnostic from `DataTier` down to `ResourceSnapshot`;
no Azure-specific assumptions in the read path.

> Naming note: this is **orthogonal** to Phase 3 (cross-Entra-tenant
> Azure). Phase 3 = same provider, different identity provider tenant.
> Phase 6 = different cloud providers entirely. They can ship in either
> order; Phase 6 has no dependency on Phase 3.

### 6.1 Provider model

- New enum `cloudguardiq.core.enums.CloudProvider`:
  - `AZURE = "azure"` (default)
  - `AWS = "aws"`
  - `GCP = "gcp"`
- Add `provider: CloudProvider = AZURE` to `SubscriptionRecord`,
  `ResourceSnapshot`, `FindingResult`. Backfill existing rows to `azure`
  via a one-off script (mirror `scripts/backfill_tenant_id.py`).
- Rename Pydantic field `subscription_id` → `account_id` in the wire
  payload but keep `subscription_id` as a serialized alias for one
  release for backward compatibility.

### 6.2 Provider-specific validation

`AddSubscriptionRequest` field validators:

| Provider | Format | Regex |
|---|---|---|
| Azure | 36-char GUID | existing `_GUID_RE` |
| AWS   | 12-digit account id | `^\d{12}$` |
| GCP   | project id | `^[a-z][a-z0-9-]{4,28}[a-z0-9]$` |

Reject early with `422` and a vendor-specific hint when the format
doesn't match the chosen provider.

### 6.3 Adapters — implement two more

`AdapterBase` already exists; add:

- `cloudguardiq/adapters/aws_adapter.py`
  - **Resources:** AWS Resource Explorer (cross-region) or Config
    aggregator as a fallback.
  - **Auth:** `sts:AssumeRole` into a customer-provided cross-account
    role (CloudGuardIQ AWS account is the trusted principal).
  - **Cost:** Cost Explorer API.
  - **Tier 2 enrichment:** Security Hub findings.
  - **Tier 3 enrichment:** GuardDuty / Inspector.
- `cloudguardiq/adapters/gcp_adapter.py`
  - **Resources:** Cloud Asset Inventory `searchAllResources`.
  - **Auth:** Workload Identity Federation pool linked to the
    CloudGuardIQ MSI (no service-account keys).
  - **Cost:** BigQuery billing export (or Cloud Billing API for live).
  - **Tier 2 enrichment:** Security Command Center findings.
  - **Tier 3 enrichment:** SCC Premium.

Factory `cloudguardiq/adapters/__init__.py::build_adapter(record)`
routes by `record.provider`.

### 6.4 Provider-aware access probe

Refactor `cloudguardiq/adapters/access_probe.py` into a strategy:

```py
async def probe_subscription_access(record: SubscriptionRecord) -> AccessProbeResult:
    match record.provider:
        case CloudProvider.AZURE: return await _probe_azure(record)
        case CloudProvider.AWS:   return await _probe_aws(record)   # sts:GetCallerIdentity
        case CloudProvider.GCP:   return await _probe_gcp(record)   # cloudresourcemanager.projects.get
```

The route returns `400 access_denied` with a vendor-specific
`grant_command` (see 6.5) on failure, mirroring the existing Azure
behaviour.

### 6.5 Onboarding hint per provider

`GET /onboarding/info?provider=azure|aws|gcp` returns:

| Provider | Field set |
|---|---|
| Azure | existing: `azure_principal_id`, `az_command_template` |
| AWS   | `aws_account_id` (CloudGuardIQ's account), `aws_external_id` (per-tenant), CloudFormation `iam_role_template_url`, terraform snippet |
| GCP   | `workload_identity_pool`, `provider_resource_name`, `gcloud add-iam-policy-binding` template |

### 6.6 Rule registry namespacing

Rules in `cloudguardiq/adapters/rules/` already operate on
`ResourceSnapshot` (cloud-agnostic by design). Two acceptable shapes:

- **(a) Tag rules** with `supported_providers: set[CloudProvider]` and
  filter inside `PolicyEngine.evaluate()`.
- **(b) Folder split** under `rules/{azure,aws,gcp,common}/`.

Default to (a) — less disruptive, lets a rule like
*"object storage bucket is publicly readable"* match Azure Blob, S3
*and* GCS once the snapshots are normalized.

### 6.7 Frontend

- `frontend/src/components/settings/SubscriptionList.tsx` gains a
  provider tabbar (`Azure | AWS | GCP`); each tab has its own field
  list, validator regex and copy-pasteable grant command from
  `GET /onboarding/info?provider=...`.
- `DataTierBadge` and `DefenderAutoBadge` already render
  vendor-neutral copy (Phase 2.6) — reuse as-is.
- Findings page filters: provider chip on every row.

### 6.8 Terraform

- New IAM resources outside the main module:
  - AWS: a published CloudFormation template (StackSet) that creates
    `CloudGuardIQReader` role with `ReadOnlyAccess` and a trust policy
    pointing at the CloudGuardIQ AWS account + per-tenant `external_id`.
  - GCP: a Workload Identity Pool + provider in the CloudGuardIQ host
    project; customer-side `gcloud` commands surfaced in the UI.
- New env vars `CLOUDGUARDIQ_AWS_ACCOUNT_ID`,
  `CLOUDGUARDIQ_GCP_WORKLOAD_IDENTITY_POOL` on Container App and
  Function App.

### 6.9 Tests

- `tests/adapters/test_aws_adapter.py` (mocked `boto3`).
- `tests/adapters/test_gcp_adapter.py` (mocked Cloud Asset client).
- `tests/api/test_subscriptions_routes.py` — add coverage for
  provider-specific validation and `400 access_denied` payload shape.
- `tests/api/test_onboarding.py` — each provider returns the
  correct field set.

### 6.10 Short-term guard (interim ship-blocker)

Until 6.1–6.9 land, the API should **fail fast** when a non-Azure
identifier is supplied: detect AWS account-id pattern (`^\d{12}$`) and
GCP project-id pattern, return `400 unsupported_provider` with
`"AWS / GCP support is on the roadmap (Phase 6); CloudGuardIQ currently
supports Azure only."`. This avoids the silent-zero-findings trap.

**Exit criteria:** a tenant can link an AWS account *or* a GCP project
through the Settings UI, the access probe verifies cross-cloud RBAC,
the scan timer fans out to the correct adapter, and at least one Tier 1
rule from each provider produces a finding end-to-end.

---

## Cross-phase definition of done (every phase)

- [ ] Tests written first; coverage >= 80%.
- [ ] `python -m pytest tests/ -x --tb=short` green.
- [ ] `ruff check cloudguardiq/` + `mypy cloudguardiq/` green.
- [ ] `terraform validate` green.
- [ ] Conventional commits (`feat:`, `fix:`, `test:`, `docs:`).
- [ ] Deployed to `dev` environment and smoke-tested.
- [ ] No new `azure.*` imports in `cloudguardiq/policy/`.
- [ ] No hardcoded subscription IDs.

---

## Suggested sequencing

| Phase | Risk                          | Customer value             | Recommended order              |
| ----- | ----------------------------- | -------------------------- | ------------------------------ |
| 0     | None                          | Alignment                  | First                          |
| 1     | Medium (data model)           | Invisible                  | Must precede Phase 2           |
| 2     | Medium                        | High (Settings UI works)   | After Phase 1                  |
| 3     | High (cross-tenant auth)      | Very high (real SaaS)      | After Phase 2, separate epic   |
| 4     | Medium (ops)                  | Stability                  | When >50 subs connected        |
| 5     | Low                           | Incremental                | Rolling backlog                |
| 6     | High (new clouds)             | Very high (TAM x3)         | Parallel to Phase 3 / 4        |

Ship **Phase 1 + 2 together** to unlock the Settings UI. Treat **Phase 3**
as its own epic — don't let it block the Settings UI launch.
