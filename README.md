# CloudGuardIQ

Azure-native SaaS combining **CSPM** (Cloud Security Posture Management) and **FinOps** cost
governance with **AI-generated remediation** powered by GPT-5.1.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Data Models](#data-models)
- [Security Rules](#security-rules)
- [API Endpoints](#api-endpoints)
- [Authentication](#authentication)
- [Multi-tenant SaaS](#multi-tenant-saas)
- [Local Development Setup](#local-development-setup)
- [Azure Deployment](#azure-deployment)
- [CI/CD Pipelines](#cicd-pipelines)
- [Testing](#testing)
- [Environment Variables](#environment-variables)
- [Infrastructure Variables (Terraform)](#infrastructure-variables-terraform)
- [Terraform Outputs](#terraform-outputs)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│  React 18 + TypeScript + Tailwind  (Static Web App)             │
│  MSAL browser auth → Azure AD tokens                            │
└──────────────────────┬───────────────────────────────────────────┘
                       │  REST / Bearer JWT
┌──────────────────────▼───────────────────────────────────────────┐
│  FastAPI Backend  (Container App)                                │
│  ┌──────────┐  ┌─────────────┐  ┌────────────────┐              │
│  │ API Layer│→ │PolicyEngine │→ │ ScanPipeline   │              │
│  └──────────┘  └─────────────┘  └───────┬────────┘              │
│                                         │                        │
│  ┌──────────────────────────────────────▼─────────────────────┐  │
│  │  AzureAdapter                                              │  │
│  │  ├─ NativeScanner (Tier 1 — Resource Graph + 52 rules)     │  │
│  │  ├─ Vendor CSPM    (Tier 2 — auto-detected, free)          │  │
│  │  └─ Vendor deep    (Tier 3 — auto-detected, paid plans)    │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────┬───────────────────────────────────────────┘
                       │  Service Bus queue
┌──────────────────────▼───────────────────────────────────────────┐
│  Azure Functions (Timer + Service Bus triggers)                  │
│  ├─ scan_trigger      — scheduled every 6 hours                  │
│  └─ ai_worker_trigger — processes findings → GPT-5.1              │
│     └─ RemediationEngine → Terraform fix, CLI fix, savings       │
└──────────────────────┬───────────────────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────────────────┐
│  Azure Cosmos DB (serverless)                                    │
│  Containers: snapshots │ findings │ remediations │ system │ billing │ subscriptions │ tenant_consents │ onboarding_sessions │
└──────────────────────────────────────────────────────────────────┘
```

### Tiered Data Source Strategy (cloud-agnostic)

`DataTier` describes *signal richness*, not a vendor. The same enum values
work across Azure, AWS, and GCP; canonical `TIER2_ENRICHED` / `TIER3_DEEP`
names are aliases of the legacy Azure-specific values so stored data and
existing rules remain unchanged.

| Tier | Canonical name | Azure | AWS | GCP |
|------|----------------|-------|-----|-----|
| **T1** | `TIER1_NATIVE` | Resource Graph + Cost Mgmt | Config / Cost Explorer | Asset Inventory / Billing |
| **T2** | `TIER2_ENRICHED` (alias of `TIER2_FREE_CSPM`) | Defender for Cloud (free CSPM) | Security Hub | Security Command Center |
| **T3** | `TIER3_DEEP` (alias of `TIER3_PAID`) | Defender for Cloud (paid plans) | GuardDuty / Inspector | SCC Premium |

Vendor security services are **never** a hard dependency. All vendor API
calls are wrapped in `try/except` with fallback to empty enrichment, and
CloudGuardIQ auto-detects them on every plan at no extra charge.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | React 18, TypeScript, Tailwind CSS 4, MSAL |
| **Backend API** | Python 3.12, FastAPI, Pydantic v2, uvicorn |
| **AI** | Azure OpenAI GPT-5.1 (structured JSON mode) |
| **Database** | Azure Cosmos DB (serverless, NoSQL) |
| **Messaging** | Azure Service Bus |
| **Identity** | Azure AD / Entra ID, MSAL, RBAC (DefaultAzureCredential) |
| **Infra** | Terraform (AzureRM 3.100+) |
| **Observability** | Application Insights, Log Analytics |
| **CI/CD** | GitHub Actions (OIDC workload identity) |
| **Quality** | pytest, ruff, mypy |

---

## Project Structure

```
cloudguardiq/
├── cloudguardiq/               # Python backend
│   ├── adapters/               # Cloud API adapters (Azure SDK)
│   │   ├── base.py             # AdapterBase — ONLY interface to cloud APIs
│   │   ├── azure_adapter.py    # 3-tier Azure scanning orchestrator
│   │   ├── native_scanner.py   # Resource Graph queries + rule registry
│   │   └── rules/              # PolicyRule implementations
│   │       ├── storage.py      # STOR-001 .. STOR-009
│   │       ├── compute.py      # VM-001 .. VM-008
│   │       ├── network.py      # NSG-001 .. NSG-003
│   │       ├── iam.py          # IAM-001 .. IAM-003
│   │       ├── keyvault.py     # KV-001 .. KV-005
│   │       └── finops.py       # FINOPS-001 .. FINOPS-008
│   ├── ai/                     # AI remediation
│   │   ├── remediation_engine.py  # GPT-5.1 structured output
│   │   └── prompt_templates.py    # System + user prompts
│   ├── api/                    # FastAPI REST layer
│   │   ├── main.py             # Route definitions
│   │   └── auth.py             # JWT validation (Azure AD JWKS)
│   ├── core/                   # Shared models & config
│   │   ├── config.py           # Settings (pydantic-settings)
│   │   ├── database.py         # CosmosRepository (async, RBAC)
│   │   ├── enums.py            # DataTier, Severity, FindingType, etc.
│   │   └── models.py           # ResourceSnapshot, FindingResult, RemediationCard
│   ├── pipeline/               # Scan orchestration
│   │   ├── scan_pipeline.py    # End-to-end scan workflow
│   │   └── ai_worker.py        # Service Bus → AI processing
│   ├── policy/                 # Rule evaluation (NO Azure SDK imports)
│   │   └── engine.py           # PolicyEngine
│   ├── healing/                # Self-healing modules
│   │   └── drift_detector.py   # Config drift detection
│   ├── billing/                # (placeholder) Stripe billing
│   ├── notifications/          # (placeholder) Alert routing
│   └── reports/                # (placeholder) Report generation
├── frontend/                   # React SPA
│   ├── src/
│   │   ├── pages/              # Dashboard, Findings, FinOps, AIFix, etc.
│   │   ├── components/         # UI components (dashboard, findings, layout)
│   │   ├── api/                # Axios client with MSAL token injection
│   │   ├── auth/               # MSAL config + RequireAuth wrapper
│   │   └── types/              # TypeScript type definitions
│   ├── package.json
│   └── vite.config.ts
├── infra/                      # Terraform IaC
│   ├── main.tf                 # All Azure resources
│   ├── variables.tf            # Input variables
│   └── outputs.tf              # Output values + .env generators
├── tests/                      # pytest test suite (324 tests, 80%+ coverage)
│   ├── adapters/
│   ├── api/
│   ├── core/
│   ├── policy/
│   └── conftest.py             # Shared fixtures
├── Dockerfile                  # Backend container image
├── function_app.py             # Azure Functions entry point
├── pyproject.toml              # Python project metadata
├── .env.example                # Environment variable template
└── .github/workflows/
    ├── ci.yml                  # Lint, type-check, test, TF validate
    ├── infra.yml               # Terraform plan/apply (OIDC)
    └── deploy.yml              # Build & deploy frontend + backend
```

---

## Data Models

### ResourceSnapshot

Represents a point-in-time capture of an Azure resource.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Cloud-agnostic ID: `azure/vm/{sub}/{rg}/{name}` |
| `provider` | `CloudProvider` | `AZURE`, `AWS`, `GCP`, `TERRAFORM` |
| `subscription_id` | `str` | Azure subscription ID |
| `resource_group` | `str` | Resource group name |
| `resource_type` | `str` | e.g. `Microsoft.Compute/virtualMachines` |
| `resource_name` | `str` | Resource display name |
| `region` | `str` | Azure region |
| `config` | `dict` | Normalized resource properties |
| `cost_monthly` | `float` | Monthly cost from Cost Management API |
| `tags` | `dict` | Resource tags |
| `data_tier` | `DataTier` | `TIER1_NATIVE`, `TIER2_ENRICHED`/`TIER2_FREE_CSPM`, `TIER3_PAID` |
| `raw_hash` | `str` | SHA256 of config for drift detection |
| `captured_at` | `datetime` | Snapshot timestamp |

### FindingResult

A security, cost, or compliance finding produced by the PolicyEngine.

| Field | Type | Description |
|-------|------|-------------|
| `finding_id` | `str` | UUID |
| `resource_snapshot` | `ResourceSnapshot` | Associated resource |
| `rule_id` | `str` | Rule identifier (e.g. `STOR-001`) |
| `severity` | `Severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` |
| `finding_type` | `FindingType` | `SECURITY`, `FINOPS`, `COMPLIANCE` |
| `description` | `str` | Human-readable description |
| `evidence` | `dict` | What triggered the finding |
| `compliance_frameworks` | `list[str]` | e.g. `["CIS_3.1", "SOC2_CC6.1"]` |
| `waste_monthly_usd` | `float` | Monthly cost waste |
| `priority_score` | `float` | 0–100 (severity × 0.5 + cost × 0.3 + compliance × 0.2) |

### RemediationCard

AI-generated fix plan for a finding.

| Field | Type | Description |
|-------|------|-------------|
| `card_id` | `str` | UUID |
| `finding_result` | `FindingResult` | The finding being remediated |
| `narrative` | `str` | Plain-English explanation |
| `terraform_fix` | `str` | Ready-to-deploy HCL code |
| `cli_fix` | `str` | Equivalent Azure CLI commands |
| `confidence_qualifier` | `str` | Data tier confidence context |
| `estimated_savings_usd` | `float` | Projected monthly savings |
| `model_version` | `str` | GPT model used |

---

## Security Rules

52 built-in rules across 6 categories:

| Category | Rules | Examples |
|----------|-------|---------|
| **Storage** | STOR-001 – STOR-009 | Public blob access, HTTPS-only, shared key auth |
| **Compute** | VM-001 – VM-008 | Disk encryption, idle VMs, unmanaged disks, missing backups |
| **Network** | NSG-001 – NSG-003 | Open RDP (3389), SSH (22) to internet |
| **IAM** | IAM-001 – IAM-003 | Overly broad role assignments |
| **Key Vault** | KV-001 – KV-005 | Soft delete, purge protection, public access |
| **FinOps** | FINOPS-001 – FINOPS-008 | Unattached disks, idle VMs, orphan IPs, AKS autoscaler |

Rules operate **only** on `ResourceSnapshot` objects — the `cloudguardiq/policy/`
module never imports the Azure SDK.

---

## API Endpoints

All endpoints except `/health` require a Bearer JWT from Azure AD.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check (no auth) |
| `POST` | `/scan` | Run synchronous scan |
| `POST` | `/scan/trigger` | Queue async scan via Service Bus |
| `GET` | `/scan/{scan_id}/status` | Get scan result by ID |
| `GET` | `/findings` | List remediation cards (sorted by priority) |
| `GET` | `/findings/{finding_id}` | Get single remediation card |
| `GET` | `/findings/{finding_id}/terraform` | Get Terraform fix as plain text |
| `GET` | `/subscriptions` | List the tenant's linked Azure subscriptions |
| `POST` | `/subscriptions` | Link a subscription (validates GUID + tier cap; `402` on cap exceeded) |
| `PATCH` | `/subscriptions/{id}` | Rename or enable/disable a subscription |
| `DELETE` | `/subscriptions/{id}` | Unlink a subscription |
| `GET` | `/subscriptions/consent-url` | Build the Azure AD admin-consent URL for a customer tenant (used by the onboarding wizard) |
| `GET` | `/subscriptions/consent-callback` | Records admin consent after Azure AD redirects the customer back to the SPA |
| `GET` | `/subscriptions/onboarding-template` | Returns the one-click ARM "Deploy to Azure" URL that assigns Reader to CloudGuardIQ's service principal |
| `POST` | `/subscriptions/onboarding-sessions` | Start a customer onboarding session and return current status + consent URL |
| `GET` | `/subscriptions/onboarding-sessions/{session_id}` | Read onboarding-session status (auto-advances to `pending_reader` after consent is detected) |
| `POST` | `/subscriptions/onboarding-sessions/{session_id}/reader-granted` | Operator confirms Reader role was granted in customer tenant |
| `POST` | `/subscriptions/onboarding-sessions/{session_id}/discover` | Discover visible customer subscriptions and cache discovered IDs on the session |
| `POST` | `/subscriptions/onboarding-sessions/{session_id}/connect` | Connect selected (or all discovered) subscriptions and mark onboarding completed |
| `GET` | `/subscriptions/discover` | Lists every subscription visible to CloudGuardIQ in the customer tenant (manual/advanced troubleshooting endpoint) |
| `GET` | `/onboarding/info` | Returns CloudGuardIQ's service-principal object id + the manual `az role assignment` template |
| `GET` | `/billing/plans` | Public plan catalog (no auth) |
| `GET` | `/billing/status` | Current tier, Stripe customer, usage |
| `POST` | `/billing/checkout` | Create a Stripe checkout session |
| `GET` | `/config` | Public client config (`demo_mode`, `client_id`, `version`) |

---

## Authentication

CloudGuardIQ uses **RBAC everywhere** — no API keys or shared secrets.

### Backend → Azure Services

All services authenticate via `DefaultAzureCredential` (managed identity in
Azure, `az login` locally):

| Service | Auth Method |
|---------|-------------|
| Cosmos DB | `DefaultAzureCredential` → Cosmos DB Built-in Data Contributor |
| Azure OpenAI | `DefaultAzureCredential` → Cognitive Services OpenAI User |
| Resource Graph | `DefaultAzureCredential` → Reader |
| Cost Management | `DefaultAzureCredential` → Reader |
| Service Bus | `DefaultAzureCredential` -> Azure Service Bus Data Owner (Functions) / Data Sender (API) |
| Function App Storage | Managed identity → Storage Blob Data Owner |

### Frontend → Backend

1. User signs in via **MSAL** (Azure AD SPA flow)
2. Frontend obtains a token scoped to `https://management.azure.com/.default`
3. Token sent as `Authorization: Bearer <token>` on every API call
4. Backend validates JWT against Azure AD JWKS keys
5. On 401, frontend auto-redirects to MSAL login

### CI/CD → Azure

GitHub Actions authenticates via **OIDC workload identity federation** — no
stored secrets for Azure credentials.

### App Registrations

| App | Client ID | Purpose |
|-----|-----------|---------|
| **CloudGuardIQ-dev** | From Terraform output `azure_ad_client_id` | User login (MSAL SPA flow), JWT validation |
| **CloudGuardIQ-GitHub-OIDC** | GitHub secret `AZURE_CLIENT_ID` | CI/CD pipeline OIDC auth only (no redirect URIs) |

> **Important:** The frontend uses `APP_CLIENT_ID` (CloudGuardIQ-dev) for MSAL,
> not `AZURE_CLIENT_ID` (GitHub OIDC). These are different app registrations.

---

## Multi-tenant SaaS

CloudGuardIQ is a multi-tenant SaaS — each customer's data is isolated by the
Azure AD `tid` claim from their JWT, and customers manage their own Azure
subscriptions from the **Settings → Azure Subscriptions** page rather than
relying on a deploy-time `AZURE_SUBSCRIPTION_ID` env var.

### Tenant isolation

- Every `ResourceSnapshot`, `FindingResult`, `RemediationCard`, and scan
  result document carries a `tenant_id` field.
- Cosmos queries always filter by `tenant_id` from the caller's JWT — no
  cross-tenant reads are possible even with guessed IDs.
- The `subscriptions` Cosmos container (PK `/tenant_id`) holds each tenant's
  linked subscriptions; `/scan`, `/findings`, etc. enforce a 403
  `subscription_not_linked` error when a tenant requests data for a
  subscription they have not added.

### Plan catalog (single source of truth)

Plan limits are scaled on **resources**, **subscriptions**, **AI usage**,
and **scan frequency** -- the same axes used by category-leading CSPM
products. No vendor capability (Defender, Security Hub, SCC) is ever
gated behind a paywall. The catalog lives in
[`cloudguardiq/billing/plans.py`](cloudguardiq/billing/plans.py) and is
exposed publicly at `GET /billing/plans`.

| Plan | Price | Subscriptions | Resources / scan | Scan cadence | AI remediations / mo | Self-healing |
|------|-------|---------------|------------------|--------------|----------------------|--------------|
| **Free** | $0 | 1 | 100 | Daily | 5 | -- |
| **Starter** (`PRO` wire value) | $49/mo | 3 | 1,000 | Hourly | 100 | -- |
| **Enterprise** | $299/mo | unlimited | unlimited | 15 min | unlimited | yes |

Enforcement is wired everywhere a quota-bearing action can occur:

| Path | What's enforced |
|------|-----------------|
| `POST /scan` | resources/scan (middleware) |
| `POST /subscriptions` | subscription cap (route handler) |
| `POST /findings/{id}/generate-remediation` | AI quota (shared helper) |
| Service Bus producer (`ScanPipeline._queue_findings`) | top-N by priority within remaining AI quota |
| Service Bus consumer (`AIWorker.process_message`) | AI quota (defense-in-depth) |
| Timer trigger (`scan_trigger`) | per-tier scan cooldown via `last_scan_at` |

All over-cap responses return `HTTP 402 upgrade_required` with
`{ current_tier, limit, cap, current }` so the UI can surface a clear
upgrade prompt.

### App-registration audience

The CloudGuardIQ Azure AD app is provisioned with
`sign_in_audience = AzureADMultipleOrgs`, which lets users from any Entra
tenant sign in. **Phase 3 cross-tenant scanning is now shipped:** customers
in a different Entra tenant can self-onboard their Azure subscriptions
after granting admin consent. See the next section for the flow.

### Connecting subscriptions from another Entra tenant

CloudGuardIQ runs as a multi-tenant Azure AD app. Customers in a
*different* Entra tenant (call it tenant **B**) can self-onboard their
Azure subscriptions to a CloudGuardIQ deployment running in your tenant
(tenant **A**) by following the steps below. The whole flow is designed
to take under 15 minutes from the customer's first click.

#### Roles required

| Role | Where | Used for |
|------|-------|----------|
| **Global Administrator** *(or Privileged Role Admin)* | Tenant **B** | Granting tenant-wide admin consent on the multi-tenant app. |
| **Owner / User Access Administrator** | Each subscription in tenant **B** that will be linked | Assigning the `Reader` role to the CloudGuardIQ service principal. |
| Any signed-in user | Tenant **A** (the CloudGuardIQ frontend) | Driving the onboarding wizard and submitting `POST /subscriptions`. |

#### Pre-flight checklist (operator side, tenant A)

Run these once, before any customer onboards.

**Automated by `terraform apply` (no operator action needed):**

- [x] App registration created with
      `sign_in_audience = AzureADMultipleOrgs` (multi-tenant).
- [x] Client secret provisioned and injected into the Container App
      and Function App as `CLOUDGUARDIQ_AZURE_CLIENT_SECRET`
      (used by `AzureCustomerCredentialFactory` for cross-tenant calls).
- [x] Consent callback Reply URL registered on the app registration's
      `web.redirect_uris`:
      `https://<frontend-host>/settings?consent=callback`,
      plus everything in `var.consent_redirect_uris`
      (default includes `http://localhost:3000/settings?consent=callback`
      for dev).
- [x] `CLOUDGUARDIQ_CONSENT_REDIRECT_URI` env var injected into the
      Container App and Function App and pointed at the same Reply URL,
      so `GET /subscriptions/consent-url` builds the correct
      `redirect_uri` automatically.
- [x] `tenant_consents` Cosmos container created
      (PK `/customer_tenant_id`).
- [x] `onboarding_sessions` Cosmos container created
      (PK `/operator_tenant_id`).
- [ ] `CLOUDGUARDIQ_ONBOARDING_TEMPLATE_URI` set to a public HTTPS URL
      hosting [`infra/templates/cloudguardiq-reader.json`](infra/templates/cloudguardiq-reader.json)
      (e.g. raw GitHub URL or an Azure Storage blob). Drives the
      **Deploy to Azure** button in step 3 of the wizard. Empty value
      disables one-click deploy (the `az role assignment create`
      fallback still works). Wired through the Terraform variable
      `onboarding_template_uri`.

**Manual one-time setup (cannot be automated by Terraform):**

- [ ] **Publisher verification** completed on the app registration via
      Microsoft Partner Center. Without it Azure AD warns customers
      the app is unverified, and many tenants block consent outright.
      See <https://learn.microsoft.com/azure/active-directory/develop/publisher-verification-overview>.
- [ ] **Home-tenant admin consent** granted once on tenant **A** for
      the API permissions declared on the app registration. From a
      shell signed in to a Global Admin of tenant **A**:

      ```bash
      az ad app permission admin-consent --id <cgiq-client-id>
      ```

      (The client id is exposed by the Terraform output
      `azure_ad_client_id`.)

**Optional:**

- [ ] Replace the client secret with a certificate by setting
      `CLOUDGUARDIQ_AZURE_CERTIFICATE_PATH` (preferred for production).
      `AzureCustomerCredentialFactory` picks the certificate first when
      both are present.
- [ ] Add custom production hostnames (e.g. `app.example.com`) to
      `consent_redirect_uris` in `terraform.tfvars` so admin-consent
      callbacks for those hosts are also accepted.

#### Onboarding wizard (UI-driven, recommended)

The Settings page renders a **Connect another tenant** card backed by
[`frontend/src/components/settings/ConnectTenantWizard.tsx`](frontend/src/components/settings/ConnectTenantWizard.tsx).
Clicking **Start Onboarding** creates one backend onboarding session and
then advances by status (`pending_consent` → `pending_reader` →
`pending_discovery` → `subscriptions_discovered` → `completed`).

| Stage | Primary actor | Action | UI button | Backend endpoint |
|-------|---------------|--------|-----------|------------------|
| 1. Start session | **Operator (CloudGuardIQ tenant)** | Enter customer tenant GUID and initialize the workflow. | **Start Onboarding** | `POST /subscriptions/onboarding-sessions` |
| 2. Grant admin consent | **Customer Global Admin / Privileged Role Admin** | Open the generated consent URL and click **Accept**. | **Open Admin Consent** | `GET /subscriptions/consent-url` (via response `consent_url`) and `GET /subscriptions/consent-callback` (AAD redirect) |
| 3. Confirm Reader role | **Customer Subscription Owner/User Access Admin** performs RBAC grant; **Operator** acknowledges in wizard | Assign Reader to CloudGuardIQ service principal, then confirm in UI. | **I Granted Reader Role** | `POST /subscriptions/onboarding-sessions/{session_id}/reader-granted` |
| 4. Discover subscriptions | **Operator** | Query visible subscriptions in customer tenant. | **Discover Subscriptions** | `POST /subscriptions/onboarding-sessions/{session_id}/discover` |
| 5. Connect subscriptions | **Operator** | Connect discovered subscriptions in one action. | **Connect All Discovered** | `POST /subscriptions/onboarding-sessions/{session_id}/connect` |

#### Actor-to-action quick reference

| Actor | Required role | What they do |
|------|----------------|--------------|
| CloudGuardIQ Operator | Any signed-in user in operator tenant | Starts session, refreshes status, discovers and connects subscriptions. |
| Customer Admin | Global Administrator or Privileged Role Administrator in customer tenant | Grants tenant-wide admin consent on the CloudGuardIQ multi-tenant app. |
| Customer Subscription Admin | Owner or User Access Administrator on each target subscription | Assigns `Reader` RBAC for the CloudGuardIQ enterprise app/service principal. |

#### Session-based API sequence (technical reference)

1. **Create session**

```http
POST /subscriptions/onboarding-sessions
Content-Type: application/json

{
  "customer_tenant_id": "<TenantB-guid>"
}
```

Returns:

```json
{
  "session_id": "<hex>",
  "customer_tenant_id": "<tenant-guid>",
  "status": "pending_consent",
  "consent_url": "https://login.microsoftonline.com/.../adminconsent...",
  "discovered_subscription_ids": [],
  "connected_subscription_ids": []
}
```

2. **Customer admin completes consent**

- Customer admin opens `consent_url` and accepts.
- Azure AD redirects to `/settings?consent=callback&tenant=<tid>&admin_consent=True`.
- [`frontend/src/pages/Settings.tsx`](frontend/src/pages/Settings.tsx) records callback through:

  ```http
  GET /subscriptions/consent-callback?tenant=<TenantB-guid>&admin_consent=True
  ```

- Subsequent session reads auto-advance to `pending_reader` once consent is active.

3. **Reader RBAC grant + operator confirmation**

Use either one-click template or CLI:

- `GET /subscriptions/onboarding-template?tenant_id=<TenantB-guid>&scope=managementGroup`
- `GET /onboarding/info` (manual command template)

Then operator confirms in the wizard:

```http
POST /subscriptions/onboarding-sessions/{session_id}/reader-granted
```

4. **Discover and connect**

```http
POST /subscriptions/onboarding-sessions/{session_id}/discover
POST /subscriptions/onboarding-sessions/{session_id}/connect
Content-Type: application/json

{
  "subscription_ids": ["<sub-guid-1>", "<sub-guid-2>"]
}
```

If `subscription_ids` is omitted, the API connects all discovered IDs.
Session status moves to `completed` after successful linking.

#### Common onboarding failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `400 invalid_tenant_id` when starting session | `customer_tenant_id` is not a GUID | Re-enter the correct Entra tenant ID and restart session. |
| Session remains `pending_consent` | Customer admin has not accepted consent yet | Open `consent_url`, complete consent, then click **Refresh Status**. |
| `400 consent_failed` in callback | Admin declined or callback carried error | Re-run consent and accept prompt. |
| Discover/connect returns `400 access_denied` or `reader_role_required` | Reader RBAC missing or not propagated | Grant Reader role, wait up to 5 minutes, click **I Granted Reader Role**, retry discovery. |
| Start onboarding returns `500`/`503` | `onboarding_sessions` container/repo not configured | Apply latest Terraform and ensure `CLOUDGUARDIQ_COSMOS_CONTAINER_ONBOARDING_SESSIONS` is set. |

#### Manual Reader grant command (customer tenant shell)

Inside tenant **B**, a subscription **Owner** grants the CloudGuardIQ
enterprise application the `Reader` role. From a shell signed in to
tenant **B**:

```bash
# One-time: discover the object id of the cgiq enterprise app inside tenant B
CGIQ_OBJECT_ID=$(az ad sp show --id <cgiq-client-id> --query id -o tsv)

# Grant Reader on each subscription the customer wants to scan
az role assignment create \
  --assignee $CGIQ_OBJECT_ID \
  --role Reader \
  --scope /subscriptions/<sub-guid>
```

> **Why Reader and not Contributor?** CloudGuardIQ never writes to
> customer subscriptions. Reader is the principle-of-least-privilege
> role for posture and cost scans. AI-suggested remediations are
> rendered as IaC diffs / `az cli` snippets the customer applies
> themselves.

Allow up to **5 minutes** for the role assignment to propagate before discovery.

#### Step 4 — First scan

The timer-driven scheduler
([`function_app.py::scan_trigger`](function_app.py)) runs every six
hours by default. For each enabled subscription it:

* Reads `customer_tenant_id` off the record.
* Builds a per-tenant credential via
  `build_default_factory(settings).for_tenant(customer_tenant_id)`.
* Runs the standard `ScanPipeline` (Resource Graph → PolicyEngine →
  optional Defender enrichment → AI worker queue).
* Stamps `last_scan_at` on success.

To scan immediately instead of waiting for the next tick, run:

```bash
curl -X POST "<api>/scan/trigger?subscription_id=<sub-guid>" \
  -H "Authorization: Bearer <token>"
```

Findings appear in the dashboard within a minute, tagged with the
linking tenant (`tenant_id`) so multi-customer operators can filter by
customer.

#### Revocation and re-linking

If the customer admin removes the CloudGuardIQ enterprise application
in tenant **B** (or revokes the Reader role), the next scan tick will
log a 401/403 from Azure AD and **auto-disable** the subscription:

```
WARNING Disabled subscription tenant=<A> sub=<sub-guid> due to auth failure (consent likely revoked)
```

The record is *not* deleted. After consent and Reader are restored, a
`PATCH /subscriptions/<sub-guid>` with `{"state": "Enabled"}` reactivates
scanning and re-attaches the historical findings.

To revoke consent server-side (e.g. customer churn), call
`TenantConsentRepository.revoke(<TenantB-guid>)` — subsequent
`POST /subscriptions` calls for that tenant will be rejected with
`400 consent_required` until consent is granted again.

#### End-to-end smoke test (single command)

With `CLOUDGUARDIQ_AUTH_DISABLED=true` (dev only) the session flow can
be exercised without a real customer admin:

```powershell
$base = "http://localhost:8000"
$tid  = "22222222-2222-2222-2222-222222222222"
$sub  = "33333333-3333-3333-3333-333333333333"

# Step 1: create onboarding session
$session = (Invoke-RestMethod -Method Post -Uri "$base/subscriptions/onboarding-sessions" -ContentType "application/json" -Body "{\"customer_tenant_id\":\"$tid\"}")
$sid = $session.session_id

# Step 2: simulate Azure AD callback after admin consent
curl "$base/subscriptions/consent-callback?tenant=$tid&admin_consent=True"

# Step 3: mark Reader grant + discover + connect
curl -X POST "$base/subscriptions/onboarding-sessions/$sid/reader-granted"
curl -X POST "$base/subscriptions/onboarding-sessions/$sid/discover"
curl -X POST "$base/subscriptions/onboarding-sessions/$sid/connect" -H 'Content-Type: application/json' `
  -d "{\"subscription_ids\":[\"$sub\"]}"

# Verify
curl "$base/subscriptions"
```

**Note for production:** Microsoft requires *publisher verification* for
non-verified multi-tenant apps before Azure AD will show consent prompts
to customers outside your tenant. Plan for the Microsoft Partner
Network step before going GA.
### Demo mode

When `CLOUDGUARDIQ_AUTH_DISABLED=true` (local/dev), the API serves canned
demo findings on `/findings` so contributors get a populated UI without an
Azure subscription. The frontend reads `GET /config` on layout mount and
displays an amber **"Demo mode"** banner across every page in this case.
Production deployments leave `AUTH_DISABLED` unset; the dashboard is empty
until the tenant links a subscription on the Settings page.

---

## Local Development Setup

### Prerequisites

- Python 3.12+
- Node.js 20+
- Azure CLI (`az login` for DefaultAzureCredential)
- Git

### 1. Clone and install Python backend

```bash
git clone https://github.com/sandyshd/CloudGuardIQ.git
cd CloudGuardIQ
pip install -e ".[dev]"
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` with your values:

```bash
# Azure AD / Entra ID
AZURE_CLIENT_ID=<your-app-client-id>
AZURE_TENANT_ID=<your-tenant-id>
AZURE_SUBSCRIPTION_ID=<your-subscription-id>   # dev-only: default for `cloudguardiq scan --subscription-id`. Production tenants link subscriptions via the Settings UI.

# Azure Cosmos DB (RBAC via DefaultAzureCredential)
CLOUDGUARDIQ_COSMOS_ENDPOINT=https://<account>.documents.azure.com:443/

# Azure OpenAI (RBAC via DefaultAzureCredential)
AZURE_OPENAI_ENDPOINT=https://<account>.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT=gpt-5.1

# Azure Service Bus (managed identity)
SERVICE_BUS_CONNECTION__fullyQualifiedNamespace=<namespace>.servicebus.windows.net

# Azure Key Vault
KEY_VAULT_URL=https://<vault>.vault.azure.net/

# Cross-tenant onboarding (optional in dev)
CLOUDGUARDIQ_CONSENT_REDIRECT_URI=http://localhost:3000/settings?consent=callback
CLOUDGUARDIQ_ONBOARDING_TEMPLATE_URI=https://raw.githubusercontent.com/<org>/<repo>/main/infra/templates/cloudguardiq-reader.json
```

> **No API keys needed.** Authentication uses `DefaultAzureCredential` which
> picks up your `az login` session locally or managed identity in Azure.

### 3. Log in to Azure

```bash
az login
```

This enables `DefaultAzureCredential` for local Cosmos DB and OpenAI access.

### 4. Run tests

```bash
python -m pytest tests/ -v --tb=short
```

### 5. Run linter and type checker

```bash
ruff check cloudguardiq/
mypy cloudguardiq/
```

### 6. Start the API server

```bash
uvicorn cloudguardiq.api.main:app --reload
```

The API is available at `http://localhost:8000`. Docs at `http://localhost:8000/docs`.

### 7. Run a CLI scan

```bash
python -m cloudguardiq scan --subscription-id <sub-id> --output json
```

### 8. Install and start the frontend

```bash
cd frontend
npm install
```

Create `frontend/.env.local`:

```bash
VITE_AZURE_CLIENT_ID=<your-app-client-id>
VITE_AZURE_TENANT_ID=<your-tenant-id>
VITE_REDIRECT_URI=http://localhost:3000
VITE_API_BASE_URL=http://localhost:8000
```

```bash
npm run dev
```

The frontend is available at `http://localhost:3000`.

---

## Azure Deployment

### Prerequisites

- Azure subscription with **Contributor** access
- Terraform 1.8+
- An Azure AD app registration for OIDC (for CI/CD)

### 1. Provision infrastructure with Terraform

#### Option A: Local deployment

```bash
az login
cd infra

terraform init \
  -backend-config="resource_group_name=tfstate-rg" \
  -backend-config="storage_account_name=<your-tfstate-storage>" \
  -backend-config="container_name=tfstate" \
  -backend-config="key=cloudguardiq.dev.tfstate" \
  -backend-config="use_azuread_auth=true"

terraform plan -var="environment=dev" -out=tfplan
terraform apply tfplan
```

#### Option B: GitHub Actions (recommended)

1. Create an Azure AD app registration (e.g. `CloudGuardIQ-GitHub-OIDC`)
2. Add a **federated credential** for GitHub Actions:
   - Entity type: **Environment**
   - Organization: `<your-github-org>`
   - Repository: `CloudGuardIQ`
   - Environment: `dev` (repeat for `staging`, `prod`)
3. Assign the following roles to the service principal:

   | Role | Scope | Purpose |
   |------|-------|---------|
   | **Contributor** | Subscription | Create/manage Azure resources |
   | **User Access Administrator** | Subscription | Create RBAC role assignments for managed identities |
   | **Application Administrator** | Azure AD (Entra ID) | Create app registrations and service principals |
   | **Storage Blob Data Contributor** | tfstate storage account | Read/write Terraform state via Azure AD auth |

   ```bash
   # Contributor (resource management)
   az role assignment create --assignee <AZURE_CLIENT_ID> \
     --role "Contributor" --scope /subscriptions/<SUBSCRIPTION_ID>

   # User Access Administrator (RBAC assignments)
   az role assignment create --assignee <AZURE_CLIENT_ID> \
     --role "User Access Administrator" --scope /subscriptions/<SUBSCRIPTION_ID>

   # Storage Blob Data Contributor (tfstate)
   az role assignment create --assignee <AZURE_CLIENT_ID> \
     --role "Storage Blob Data Contributor" \
     --scope /subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<TF_STATE_RG>/providers/Microsoft.Storage/storageAccounts/<TF_STATE_STORAGE>

   # Application Administrator (Azure AD directory role — assign via Portal)
   # Portal: Entra ID > Roles and administrators > Application Administrator > Add assignment
   ```

4. Configure GitHub repository secrets:

   | Secret | Scope | Description |
   |--------|-------|-------------|
   | `AZURE_CLIENT_ID` | Repository | App registration client ID |
   | `AZURE_TENANT_ID` | Repository | Azure AD tenant ID |
   | `AZURE_SUBSCRIPTION_ID` | Repository | Target subscription |
   | `TF_STATE_RESOURCE_GROUP` | Repository | Resource group for tfstate storage |
   | `TF_STATE_STORAGE_ACCOUNT` | Repository | Storage account for tfstate |
   | `FRONTEND_URL` | Environment | Static Web App URL (e.g. `https://<random-name>.azurestaticapps.net` — get from Azure Portal) |
   | `API_URL` | Environment | Container App URL (e.g. `https://cguardiq-dev-api.<region>.azurecontainerapps.io`) |
   | `APP_CLIENT_ID` | Environment | CloudGuardIQ-dev app client ID (for frontend MSAL auth) |
| `SWA_DEPLOYMENT_TOKEN` | Environment | Static Web App deployment token (from Portal) |
| `ONBOARDING_TEMPLATE_URI` | Repository | (Optional) Raw HTTPS URL of `infra/templates/cloudguardiq-reader.json`. Set to `https://raw.githubusercontent.com/<owner>/<repo>/<ref>/infra/templates/cloudguardiq-reader.json` to enable the cross-tenant onboarding wizard. Wired into Terraform via `TF_VAR_onboarding_template_uri` in `.github/workflows/infra.yml`. |

6. Create a GitHub environment named `dev`
7. Go to **Actions → Terraform Infrastructure → Run workflow**
8. Select environment and action (`plan` or `apply`)

### 2. What Terraform creates

| Resource | Name Pattern | Purpose |
|----------|-------------|---------|
| Resource Group | `cguardiq-{env}-rg` | Container for all resources |
| Azure AD App | `CloudGuardIQ-{env}` | SPA + API auth |
| Cosmos DB | `cguardiq-{env}-cosmos` | Serverless NoSQL (RBAC, local auth disabled) |
| Azure OpenAI | `cguardiq-{env}-openai` | GPT-5.1 deployment (local auth disabled) |
| Key Vault | `cguardiq-{env}-kv` | Application secrets (e.g. app client secret) |
| Service Bus | `cguardiq-{env}-sb` | Async findings queue |
| Container App | `cguardiq-{env}-api` | FastAPI backend |
| Function App | `cguardiq-{env}-func` | Timer scan + AI worker |
| Container Registry | `cguardiq{env}acr` | Docker image storage (Basic SKU) |
| Static Web App | `cguardiq-{env}-swa` | React frontend |
| App Insights | `cguardiq-{env}-ai` | Monitoring & tracing |
| Log Analytics | `cguardiq-{env}-law` | Log aggregation |

### 3. RBAC role assignments (auto-provisioned by Terraform)

| Principal | Role | Scope |
|-----------|------|-------|
| Container App MI | Cosmos DB Built-in Data Contributor | Cosmos DB account |
| Container App MI | Cognitive Services OpenAI User | OpenAI account |
| Container App MI | Reader | Subscription |
| Function App MI | Cosmos DB Built-in Data Contributor | Cosmos DB account |
| Function App MI | Cognitive Services OpenAI User | OpenAI account |
| Function App MI | Reader | Subscription |
| Function App MI | Storage Blob Data Owner | Function storage account |
| Function App MI | Storage Queue Data Contributor | Function storage account |
| Function App MI | Storage Table Data Contributor | Function storage account |
| Function App MI | Azure Service Bus Data Owner | Service Bus namespace |
| Container App MI | Azure Service Bus Data Sender | Service Bus namespace |
| Container App MI | AcrPull | Container Registry |
| GitHub SP | AcrPush | Container Registry |
| GitHub SP | Storage Blob Data Owner | Function storage account |
| Service Principal | Reader | Subscription |

> **Key-based authentication is disabled** on Cosmos DB
> (`local_authentication_disabled = true`) and Azure OpenAI
> (`local_auth_enabled = false`). All access uses managed identity.

### 4. Generate backend .env from Terraform

```bash
cd infra
terraform output -raw backend_env_file > ../.env
```

### 5. Generate frontend .env from Terraform

```bash
cd infra
terraform output -raw frontend_env_file > ../frontend/.env.local
```

---

## CI/CD Pipelines

### CI — Lint, Test & Validate

**File:** `.github/workflows/ci.yml`  
**Trigger:** Manual (`workflow_dispatch`)

| Job | Steps |
|-----|-------|
| **test** | `pip install -e ".[dev]"` → `ruff check .` → `mypy cloudguardiq/` → `pytest --cov --cov-fail-under=80` |
| **terraform-validate** | `terraform init -backend=false` → `terraform validate` → `terraform fmt -check` |

### Infrastructure — Terraform Plan/Apply

**File:** `.github/workflows/infra.yml`  
**Trigger:** Manual with inputs

| Input | Options | Default |
|-------|---------|---------|
| `environment` | `dev`, `staging`, `prod` | `dev` |
| `action` | `plan`, `apply` | `plan` |

**Auth:** OIDC workload identity federation (no stored Azure credentials).

**Flow:** Login → Init (Azure Blob backend with `use_azuread_auth`) → Format Check → Validate → Plan → Apply (if selected).

---

### Deploy — Build & Ship Application

**File:** `.github/workflows/deploy.yml`
**Trigger:** Manual with inputs

| Input | Options | Default |
|-------|---------|---------|
| `environment` | `dev`, `staging`, `prod` | `dev` |

**Jobs:**

| Job | Steps |
|-----|-------|
| **deploy-frontend** | `npm ci` → Build with `VITE_*` env vars → Deploy to Static Web App |
| **deploy-backend** | Azure Login → Docker build → Push to ACR → Update Container App |
| **deploy-functions** | Setup Python → Azure Login → Deploy to Azure Functions via `functions-action` |

**Frontend `VITE_*` variables** are injected as build-time env vars during `npm run build`
and baked into the static JS bundle. `VITE_AZURE_CLIENT_ID` uses the `APP_CLIENT_ID`
environment secret (CloudGuardIQ-dev app), not the `AZURE_CLIENT_ID` repository secret.

**Backend env vars** (Cosmos, OpenAI, etc.) are already set on the Container App by Terraform —
the deploy workflow only updates the container image.

**ACR name** is computed from the naming convention (`cguardiq{env}acr`) — no `ACR_NAME`
secret is needed.

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v --tb=short

# Run with coverage
python -m pytest tests/ --cov=cloudguardiq --cov-fail-under=80

# Run a specific test file
python -m pytest tests/test_ai_remediation.py -v

# Lint
ruff check cloudguardiq/

# Type check
mypy cloudguardiq/
```

**324 tests** covering adapters, API, policy engine, AI remediation, models,
pipeline, and healing modules. All external APIs (Azure, OpenAI, Cosmos) are
mocked in tests.

---

## Environment Variables

### Backend (Python)

Variables with the `CLOUDGUARDIQ_` prefix are loaded by pydantic-settings.

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_CLIENT_ID` | Yes | Azure AD app client ID |
| `AZURE_TENANT_ID` | Yes | Azure AD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | No | **Dev/CLI only.** Production tenants link subscriptions per-tenant in Cosmos via Settings UI. |
| `CLOUDGUARDIQ_COSMOS_CONTAINER_SUBSCRIPTIONS` | No | Cosmos container for tenant-managed subscriptions (default: `subscriptions`) |
| `CLOUDGUARDIQ_PRO_MAX_SUBSCRIPTIONS` | No | Pro-tier subscription cap (default: `10`) |
| `CLOUDGUARDIQ_AUTH_DISABLED` | No | When `true`, /findings serves canned demo data and the UI shows a demo-mode banner |
| `CLOUDGUARDIQ_COSMOS_ENDPOINT` | Yes | Cosmos DB account endpoint |
| `CLOUDGUARDIQ_AZURE_OPENAI_ENDPOINT` | Yes | Azure OpenAI endpoint |
| `CLOUDGUARDIQ_AZURE_OPENAI_DEPLOYMENT` | No | Model deployment name (default: `gpt-5.1`) |
| `CLOUDGUARDIQ_AZURE_TENANT_ID` | Yes | Tenant ID for JWT validation |
| `CLOUDGUARDIQ_AZURE_CLIENT_ID` | Yes | Client ID for JWT audience validation |
| `CLOUDGUARDIQ_AZURE_CLIENT_SECRET` | Cross-tenant only | Client secret used by `CustomerCredentialFactory` to authenticate against customer tenants. Provisioned by Terraform. Prefer a certificate where possible. |
| `CLOUDGUARDIQ_AZURE_CERTIFICATE_PATH` | Cross-tenant only | Path to a PFX/PEM certificate for `ClientCertificateCredential`. Takes precedence over the client secret when both are set. |
| `CLOUDGUARDIQ_COSMOS_CONTAINER_TENANT_CONSENTS` | No | Cosmos container for cross-tenant admin-consent records (default: `tenant_consents`) |
| `CLOUDGUARDIQ_COSMOS_CONTAINER_ONBOARDING_SESSIONS` | No | Cosmos container for onboarding-session state (default: `onboarding_sessions`) |
| `CLOUDGUARDIQ_CONSENT_REDIRECT_URI` | Cross-tenant only | Reply URL the Azure AD admin-consent redirect returns to (must match an app-registration Reply URL). Default: `http://localhost:3000/settings?consent=callback`. |
| `CLOUDGUARDIQ_ONBOARDING_TEMPLATE_URI` | No | Public HTTPS URL hosting [`infra/templates/cloudguardiq-reader.json`](infra/templates/cloudguardiq-reader.json). Drives the **Deploy to Azure** button returned by `GET /subscriptions/onboarding-template`. Empty disables the one-click button (the `az role assignment` fallback still works). If a `https://github.com/<owner>/<repo>/blob/<ref>/<path>` URL is supplied by mistake, the API rewrites it to the matching `raw.githubusercontent.com` URL so the Azure Portal blade can fetch the JSON. |
| `SERVICE_BUS_CONNECTION__fullyQualifiedNamespace` | No | Service Bus namespace FQDN (managed identity auth) |
| `KEY_VAULT_URL` | No | Key Vault URI |

### Frontend (React)

| Variable | Description |
|----------|-------------|
| `VITE_AZURE_CLIENT_ID` | CloudGuardIQ-dev app client ID (from `APP_CLIENT_ID` secret) |
| `VITE_AZURE_TENANT_ID` | Azure AD tenant ID |
| `VITE_REDIRECT_URI` | Auth redirect URI (default: `http://localhost:3000`) |
| `VITE_API_BASE_URL` | Backend API URL (default: `/api`) |

---

## Infrastructure Variables (Terraform)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `prefix` | `string` | `cguardiq` | Resource name prefix |
| `environment` | `string` | `dev` | `dev`, `staging`, or `prod` |
| `location` | `string` | `eastus` | Azure region |
| `openai_location` | `string` | `eastus2` | Region for OpenAI (limited availability) |
| `swa_location` | `string` | `eastus2` | Region for Static Web App |
| `openai_capacity` | `number` | `10` | TPM capacity (thousands) |
| `api_container_image` | `string` | hello-world image | Docker image for backend |
| `frontend_redirect_uris` | `list(string)` | `["http://localhost:3000"]` | Additional auth redirect URIs |
| `consent_redirect_uris` | `list(string)` | `["http://localhost:3000/settings?consent=callback"]` | Extra Reply URLs for the Azure AD admin-consent callback (cross-tenant onboarding) |
| `onboarding_template_uri` | `string` | `""` | Public HTTPS URL hosting [`infra/templates/cloudguardiq-reader.json`](infra/templates/cloudguardiq-reader.json). Drives the wizard's **Deploy to Azure** button. Propagated to the Container App and Function App as `CLOUDGUARDIQ_ONBOARDING_TEMPLATE_URI`. In CI this is fed by the repository secret `ONBOARDING_TEMPLATE_URI` via `TF_VAR_onboarding_template_uri` in `.github/workflows/infra.yml`. |

---

## Terraform Outputs

| Output | Description |
|--------|-------------|
| `resource_group_name` | Resource group name |
| `azure_ad_client_id` | Azure AD app client ID |
| `azure_ad_tenant_id` | Azure AD tenant ID |
| `cosmosdb_endpoint` | Cosmos DB account endpoint |
| `openai_endpoint` | Azure OpenAI endpoint |
| `key_vault_uri` | Key Vault URI |
| `servicebus_connection_string` | Service Bus connection string (sensitive) |
| `appinsights_connection_string` | App Insights connection string (sensitive) |
| `api_url` | Backend API URL |
| `function_app_name` | Function App name |
| `frontend_url` | Frontend Static Web App URL |
| `acr_name` | Azure Container Registry name |
| `acr_login_server` | Azure Container Registry login server |
| `backend_env_file` | Ready-to-use `.env` contents |
| `frontend_env_file` | Ready-to-use frontend `.env.local` contents |

---

## License

Proprietary — All rights reserved.
