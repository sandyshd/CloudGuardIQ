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
│  │  ├─ Defender free  (Tier 2 — secure score enrichment)      │  │
│  │  └─ Defender paid  (Tier 3 — threat intelligence)          │  │
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
│  Containers: snapshots │ findings │ remediations │ system        │
└──────────────────────────────────────────────────────────────────┘
```

### Tiered Data Source Strategy

| Tier | Source | Dependency | Data |
|------|--------|------------|------|
| **Tier 1 — Native** | Azure Resource Graph + Cost Management | None (always available) | Resource config, cost, 52 policy rules |
| **Tier 2 — Free CSPM** | Defender for Cloud (free tier) | Optional — graceful degradation | Secure score, recommendations |
| **Tier 3 — Paid** | Defender for Cloud (paid plans) | Optional — graceful degradation | Threat alerts, advanced analytics |

Defender for Cloud is **never** a hard dependency. All Defender API calls are
wrapped in `try/except` with fallback to empty enrichment.

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
| `data_tier` | `DataTier` | `TIER1_NATIVE`, `TIER2_FREE_CSPM`, `TIER3_PAID` |
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
| `GET` | `/subscriptions` | List connected Azure subscriptions |

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
| Service Bus | Connection string (via Key Vault) |
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
AZURE_SUBSCRIPTION_ID=<your-subscription-id>

# Azure Cosmos DB (RBAC via DefaultAzureCredential)
CLOUDGUARDIQ_COSMOS_ENDPOINT=https://<account>.documents.azure.com:443/

# Azure OpenAI (RBAC via DefaultAzureCredential)
AZURE_OPENAI_ENDPOINT=https://<account>.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT=gpt-5.1

# Azure Service Bus
SERVICE_BUS_CONNECTION_STRING=<connection-string>

# Azure Key Vault
KEY_VAULT_URL=https://<vault>.vault.azure.net/
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
| Key Vault | `cguardiq-{env}-kv` | Service Bus connection string |
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
| `AZURE_SUBSCRIPTION_ID` | Yes | Subscription to scan |
| `CLOUDGUARDIQ_COSMOS_ENDPOINT` | Yes | Cosmos DB account endpoint |
| `CLOUDGUARDIQ_AZURE_OPENAI_ENDPOINT` | Yes | Azure OpenAI endpoint |
| `CLOUDGUARDIQ_AZURE_OPENAI_DEPLOYMENT` | No | Model deployment name (default: `gpt-5.1`) |
| `CLOUDGUARDIQ_AZURE_TENANT_ID` | Yes | Tenant ID for JWT validation |
| `CLOUDGUARDIQ_AZURE_CLIENT_ID` | Yes | Client ID for JWT audience validation |
| `CLOUDGUARDIQ_AUTH_DISABLED` | No | Set `true` to disable JWT auth (dev only) |
| `SERVICE_BUS_CONNECTION_STRING` | No | Service Bus connection (for async mode) |
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
