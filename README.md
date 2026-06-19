<div align="center">

# CloudGuardIQ

**Unified Cloud Security Posture Management (CSPM) + FinOps Cost Governance, powered by AI**

*Azure-native multi-tenant SaaS — secure, optimize, and remediate Azure, AWS, and GCP workloads from a single pane of glass.*

[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61dafb.svg)](https://react.dev/)
[![Terraform](https://img.shields.io/badge/Terraform-1.8%2B-7B42BC.svg)](https://www.terraform.io/)
[![Tests](https://img.shields.io/badge/tests-664%20passing-success.svg)](#16-testing--quality)
[![Coverage](https://img.shields.io/badge/coverage-80%25%2B-success.svg)](#16-testing--quality)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](#20-license)

</div>

---

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [Key Capabilities](#2-key-capabilities)
3. [Supported Clouds & Frameworks](#3-supported-clouds--frameworks)
4. [Solution Architecture](#4-solution-architecture)
5. [Tech Stack](#5-tech-stack)
6. [Subscription Plans](#6-subscription-plans)
7. [Repository Layout](#7-repository-layout)
8. [Prerequisites](#8-prerequisites)
9. [Quickstart (Local Development)](#9-quickstart-local-development)
10. [Production Deployment on Azure](#10-production-deployment-on-azure)
11. [Customer Onboarding](#11-customer-onboarding)
12. [Configuration Reference](#12-configuration-reference)
13. [REST API Reference](#13-rest-api-reference)
14. [Security & Compliance](#14-security--compliance)
15. [Observability & Operations](#15-observability--operations)
16. [Testing & Quality](#16-testing--quality)
17. [CI/CD](#17-cicd)
18. [Roadmap](#18-roadmap)
19. [Support](#19-support)
20. [License](#20-license)

---

## 1. Product Overview

**CloudGuardIQ** is an enterprise-grade multi-tenant SaaS platform that combines
**Cloud Security Posture Management (CSPM)**, **FinOps cost governance**, and
**AI-generated remediation** into one unified workflow. It is built cloud-natively
on Azure but scans **Azure, AWS, and GCP** environments through a pluggable
adapter framework.

### What problem does it solve?

Modern cloud teams juggle a fragmented toolchain — separate products for security
posture, cost optimization, compliance reporting, and remediation guidance. Each
tool produces siloed alerts; engineers spend hours triaging, prioritizing, and
hand-crafting fixes. CloudGuardIQ collapses this stack:

| Pain point | CloudGuardIQ answer |
|------------|--------------------|
| Hundreds of low-context CSPM alerts | Cross-signal **priority score** (severity × cost × compliance) |
| "Now what do I do?" after a finding | **GPT-5.1 remediation cards** with ready-to-deploy Terraform + Azure CLI |
| Vendor lock-in to Defender / Security Hub / SCC | **Tiered adapter strategy** — vendor enrichment is *optional*, never required |
| Cost waste hidden in security tools | First-class **FinOps rules** alongside security rules |
| Slow customer onboarding | **<15-minute multi-cloud wizard** with one-click ARM / CloudFormation / `gcloud` artifacts |
| Compliance evidence gathering | Built-in **CIS, SOC 2, ISO 27001, PCI-DSS** mapping per finding |

### Who is it for?

- **Cloud Security Engineers** — replace 3+ tools, ship fixes in IaC instead of click-ops
- **FinOps Practitioners** — surface waste alongside risk, attribute savings to remediation
- **MSPs / Operators** — onboard customer tenants in minutes, manage hundreds of subscriptions
- **Compliance & Audit Teams** — pre-mapped frameworks, exportable scorecards

---

## 2. Key Capabilities

### 2.1 Cloud Security Posture Management (CSPM)
- **70+ built-in policy rules** across Storage, Compute, Network, IAM, Key Vault, Containers
- **Cross-cloud rule packs**: Azure (52), AWS (11+), GCP (early access)
- **Continuous configuration drift detection** with SHA-256 baselining
- **Compliance mapping** — every rule carries explicit control citations for CIS Benchmarks, NIST 800-53, ISO/IEC 27001:2022, PCI-DSS v4.0, SOC 2, and HIPAA Security Rule (45 CFR §164)
- **Tier-aware enrichment** — auto-detects and consumes Microsoft Defender for Cloud,
  AWS Security Hub, and Google SCC when available, with graceful fallback

### 2.2 FinOps Cost Governance
- Dedicated `FINOPS-*` rules (idle VMs, unattached disks, orphan IPs, AKS autoscaler, oversized SKUs)
- Monthly **waste quantification per resource** via Azure Cost Management / Cost Explorer / Billing APIs
- **Projected savings** on every remediation card, stamped `DIRECT` vs `ESTIMATED`
- **Native recommender integration** (Azure Advisor / AWS / GCP) merged into the scan
- **FOCUS-normalized cost ledger** powering a vendor-neutral analytics layer:
  commitment coverage & utilization, spend forecasting, cost allocation
  (showback/chargeback) + tag coverage, budgets with breach alerting, statistical
  spend-anomaly detection, and unit economics (cost per tenant-defined unit)
- Plan-aware **cost dashboard** plus dedicated **Optimization** and **Budgets** workspaces

### 2.3 AI-Generated Remediation
- **GPT-5.1** (Azure OpenAI) in structured JSON mode for deterministic output
- Each finding produces a **Remediation Card** containing:
  - Plain-English narrative
  - Production-ready **Terraform HCL** fix
  - Equivalent **Azure CLI / AWS CLI / `gcloud`** commands
  - Confidence qualifier tied to the data tier that produced the finding
  - Estimated monthly savings (when applicable)
- Retry-with-backoff, AI quota enforcement, and per-tenant cost guardrails
- Asynchronous **Service Bus worker** pattern — non-blocking scan pipeline

### 2.4 Self-Healing (Enterprise)
- **Drift detector** continuously compares live resource hashes against baseline
- **Contract monitor** validates IaC-declared state against actual state
- **Repair agent** applies low-risk auto-remediations (Enterprise tier only, opt-in)

### 2.5 Multi-Tenant SaaS Platform
- Hard tenant isolation via Azure AD `tid` JWT claim — every Cosmos query filters by `tenant_id`
- **Cross-tenant onboarding** — operators in tenant A can enroll customers in tenant B
- **Per-tenant subscription registry** with state machine (Enabled / Disabled / Failed)
- **Stripe-powered billing** with metered usage (scans, AI remediations, subscription cap)
- **Quota enforcement** at every entry point (route, middleware, pipeline, worker)

### 2.6 Customer Onboarding Experience
- Unified **Multi-Cloud Onboarding Wizard** (5 steps) for Azure / AWS / GCP
- One-click **Deploy to Azure** ARM template (Reader RBAC grant)
- Auto-generated **CloudFormation** template (AWS) and **`gcloud` binding script** (GCP)
- Real-time **permission probe** + **scope discovery** before scan
- Auto-disable on auth failure with friendly re-link UX

### 2.7 Compliance & Reporting
- **Compliance Scorecard** per framework with drill-down to failing controls
- **Posture Score** (0–100) aggregated across severity weights
- Exportable **JSON / CSV** evidence for auditors
- Tenant-scoped **audit event log**

### 2.8 Developer & Operator Experience
- **OpenAPI 3** spec at `/docs` (Swagger UI) and `/redoc`
- **Python CLI**: `cloudguardiq scan --subscription-id <id> --output json`
- **Demo mode** (`AUTH_DISABLED=true`) for instant zero-config UI walkthroughs
- **Application Insights** distributed tracing across API → Service Bus → Worker

---

## 3. Supported Clouds & Frameworks

### Cloud providers

| Provider | Native scanner | Free vendor enrichment | Paid vendor enrichment |
|----------|----------------|------------------------|------------------------|
| **Azure** | Resource Graph + Cost Management | Defender for Cloud (free CSPM) | Defender plans (Servers, SQL, Storage, etc.) |
| **AWS** | Config / Cost Explorer | Security Hub | GuardDuty, Inspector |
| **GCP** | Asset Inventory / Billing | Security Command Center (Standard) | SCC Premium |

> Vendor enrichment is **always optional**. Every external call is wrapped in
> `try/except` with graceful fallback to native-only signal. No vendor is a
> hard dependency at any tier.

### Compliance frameworks

Every built-in rule is tagged with explicit control citations across six
framework families. The **Compliance** page renders a family-grouped scorecard
with click-through filtering to the underlying controls.

| Family | Coverage |
|--------|----------|
| CIS Benchmarks | Microsoft Azure Foundations, AWS Foundations, GCP Foundations |
| NIST SP 800-53 | Rev. 5 control IDs (`AC-*`, `SC-*`, `SI-*`, `AU-*`, …) |
| ISO/IEC 27001:2022 | Annex A controls (`A.5.*`, `A.8.*`, …) |
| PCI-DSS v4.0 | Numbered requirements (e.g. `PCI_DSS_3.5.1`, `PCI_DSS_8.3.1`) |
| SOC 2 (Type II) | Trust Services Criteria (`CC6.*`, `CC7.*`) |
| HIPAA Security Rule | 45 CFR §164.308 / §164.312 citations |

Also aligned with the Azure Well-Architected Framework Security pillar.

### Built-in rule packs

| Pack | Count | Examples |
|------|-------|----------|
| Azure — Storage | 9 | Public blob access, HTTPS-only, shared key auth |
| Azure — Compute | 8 | Disk encryption, idle VMs, unmanaged disks, missing backups |
| Azure — Network | 3 | Open RDP (3389), SSH (22) to internet |
| Azure — IAM | 3 | Overly broad role assignments, stale principals |
| Azure — Key Vault | 5 | Soft delete, purge protection, public access |
| Azure — FinOps | 8 | Unattached disks, idle VMs, orphan IPs, AKS autoscaler |
| AWS | 11+ | S3 public, EC2 metadata v1, security groups, IAM, ECR, FinOps |
| GCP | early | Compute, storage, IAM, network, registry |

All rules live in [`cloudguardiq/adapters/rules/`](cloudguardiq/adapters/rules/)
and operate exclusively on normalized `ResourceSnapshot` objects — the
`cloudguardiq/policy/` module never imports a cloud SDK.

---

## 4. Solution Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│  React 18 + TypeScript + Tailwind CSS 4  ·  Azure Static Web App          │
│  MSAL browser auth → Azure AD tokens (multi-tenant)                       │
└───────────────────────────────┬───────────────────────────────────────────┘
                                │ HTTPS / Bearer JWT
┌───────────────────────────────▼───────────────────────────────────────────┐
│  FastAPI Backend  ·  Azure Container Apps                                 │
│  ┌─────────┐  ┌──────────────┐  ┌─────────────┐  ┌────────────────────┐   │
│  │ Routes  │→ │ JWT/JWKS Auth│→ │PolicyEngine │→ │ ScanPipeline       │   │
│  └─────────┘  └──────────────┘  └─────────────┘  └─────────┬──────────┘   │
│  ┌──────────────────────────────────────────────────────────▼──────────┐  │
│  │  Adapter Layer (ONLY layer touching cloud SDKs)                     │  │
│  │  ├─ AzureAdapter  →  NativeScanner ▸ Defender enrichment ▸ Cost Mgmt│  │
│  │  ├─ AWSAdapter    →  Config / Security Hub / Cost Explorer          │  │
│  │  └─ GCPAdapter    →  Asset Inventory / SCC / Billing                │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ BillingSvc   │  │ OnboardingSvc│  │ ComplianceSvc│  │ HealingSvc   │   │
│  │ (Stripe)     │  │ (multi-cloud)│  │ (scorecards) │  │ (Enterprise) │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└───────────────────────────────┬───────────────────────────────────────────┘
                                │ Service Bus (managed identity)
┌───────────────────────────────▼───────────────────────────────────────────┐
│  Azure Functions  ·  Timer + Service Bus triggers                         │
│  ├─ scan_trigger        — scheduled scans (per-tier cooldown)             │
│  └─ ai_worker_trigger   — Findings → GPT-5.1 → RemediationCard            │
└───────────────────────────────┬───────────────────────────────────────────┘
                                │
┌───────────────────────────────▼───────────────────────────────────────────┐
│  Azure Cosmos DB (serverless, RBAC, local auth disabled)                  │
│  snapshots │ findings │ remediations │ system │ billing │                 │
│  subscriptions │ tenant_consents │ onboarding_sessions │                  │
│  cloud_connections │ audit_events │ credential_refs                       │
└───────────────────────────────────────────────────────────────────────────┘

  Azure OpenAI (GPT-5.1) · Azure Key Vault · App Insights · Log Analytics
```

### Architectural principles

1. **Strict layering** — `policy/` rules never import cloud SDKs; they evaluate
   normalized `ResourceSnapshot` objects only.
2. **Adapter isolation** — `adapters/base.py::AdapterBase` is the *only*
   interface that touches external cloud APIs.
3. **Graceful degradation** — every external call has a try/except with a
   typed fallback. A failed Defender API call never breaks a scan.
4. **RBAC everywhere** — zero shared secrets between services. All
   intra-Azure calls use Managed Identity via `DefaultAzureCredential`.
5. **Structured AI I/O** — GPT-5.1 only ever sees a typed `FindingResult`
   JSON, never raw cloud API responses.
6. **Tenant isolation by construction** — `tenant_id` is a required field on
   every persisted document; queries always include it.

### Tiered data source strategy

`DataTier` describes *signal richness*, not a specific vendor. Customers
without paid security tools still get a fully functional product.

| Tier | Canonical name | Azure | AWS | GCP |
|------|----------------|-------|-----|-----|
| **T1** | `TIER1_NATIVE` | Resource Graph + Cost Mgmt | Config + Cost Explorer | Asset Inventory + Billing |
| **T2** | `TIER2_ENRICHED` | Defender for Cloud (free CSPM) | Security Hub | Security Command Center |
| **T3** | `TIER3_DEEP` | Defender paid plans | GuardDuty + Inspector | SCC Premium |

### Core data models

| Model | Purpose | Notable fields |
|-------|---------|----------------|
| `ResourceSnapshot` | Point-in-time capture of a cloud resource | `provider`, `subscription_id`, `resource_type`, `config`, `cost_monthly`, `data_tier`, `raw_hash`, `tenant_id` |
| `FindingResult` | Security / FinOps / compliance finding | `rule_id`, `severity`, `finding_type`, `evidence`, `compliance_frameworks`, `waste_monthly_usd`, `priority_score`, `tenant_id` |
| `RemediationCard` | AI-generated fix plan | `narrative`, `terraform_fix`, `cli_fix`, `confidence_qualifier`, `estimated_savings_usd`, `model_version` |

---

## 5. Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | React 18, TypeScript 5.6, Vite 6, Tailwind CSS 4, MSAL React, Recharts, Lucide |
| **Backend API** | Python 3.12, FastAPI 0.111, Pydantic v2, uvicorn, async/await throughout |
| **Async workers** | Azure Functions (Python v2 programming model), Timer + Service Bus triggers |
| **AI** | Azure OpenAI GPT-5.1 in structured JSON mode |
| **Database** | Azure Cosmos DB (serverless NoSQL, RBAC, local auth disabled) |
| **Messaging** | Azure Service Bus (managed identity) |
| **Identity** | Azure AD / Entra ID (multi-tenant app), MSAL, `DefaultAzureCredential` |
| **Billing** | Stripe (checkout sessions, metered usage) |
| **Infrastructure** | Terraform 1.8+, AzureRM provider 3.100+ |
| **Observability** | Application Insights, Log Analytics, OpenTelemetry-compatible tracing |
| **CI/CD** | GitHub Actions with OIDC workload identity federation |
| **Quality** | pytest, pytest-asyncio, pytest-cov, ruff, mypy |

---

## 6. Subscription Plans

The plan catalog is the **single source of truth** in
[cloudguardiq/billing/plans.py](cloudguardiq/billing/plans.py) and is exposed
publicly via `GET /billing/plans`. Limits scale on the same axes as Wiz, Orca,
and Prisma Cloud: **subscriptions**, **resources per scan**, **AI usage**, and
**scan cadence**.

| | **Free** | **Starter** | **Enterprise** |
|---|---|---|---|
| **Price** | $0 | $49 / mo | $299 / mo |
| **Cloud subscriptions / accounts** | 1 | 3 | Unlimited |
| **Resources per scan** | 100 | 1,000 | Unlimited |
| **Scan cadence** | Daily | Hourly | Every 15 min |
| **AI remediation plans / month** | 5 | 100 | Unlimited |
| **Self-healing** | — | — | ✓ |
| **Priority support** | — | — | ✓ |
| **Vendor enrichment (Defender / Security Hub / SCC)** | Auto | Auto | Auto |

> Vendor enrichment is **never** gated behind a paywall. If the customer has
> Defender for Cloud enabled, CloudGuardIQ consumes it for free on all tiers.

Over-cap actions return `HTTP 402 upgrade_required` with `{ current_tier,
limit, cap, current }` so the UI can render a clear upgrade prompt. Enforcement
is wired at every quota-bearing entry point:

| Path | Enforced quota |
|------|----------------|
| `POST /scan` | Resources per scan (middleware) |
| `POST /subscriptions` | Subscription cap (route handler) |
| `POST /findings/{id}/generate-remediation` | AI quota (shared helper) |
| `ScanPipeline._queue_findings` | Top-N by priority within remaining AI quota |
| `AIWorker.process_message` | AI quota (defense-in-depth) |
| `scan_trigger` (Timer) | Per-tier scan-cadence cooldown |

---

## 7. Repository Layout

```
cloudguardiq/
├── cloudguardiq/                    # Python backend package
│   ├── adapters/                    # Cloud API adapters (ONLY cloud SDK callers)
│   │   ├── base.py                  # AdapterBase interface
│   │   ├── native_scanner.py        # Generic Tier-1 scanner + rule registry
│   │   ├── capability_detector.py   # Auto-detects Defender/SHub/SCC availability
│   │   ├── access_probe.py          # Pre-scan permission validation
│   │   ├── factory.py               # Provider → Adapter resolution
│   │   ├── azure/   aws/   gcp/     # Per-provider adapter implementations
│   │   ├── pricing/                 # SKU → cost lookup tables
│   │   └── rules/
│   │       ├── azure/               # 52 rules (storage, compute, network, iam, kv, finops)
│   │       ├── aws/                 # 11+ rules (s3, ec2, iam, registry, security_group, finops)
│   │       └── gcp/                 # Early-access rules (compute, storage, iam, network, registry)
│   ├── ai/                          # GPT-5.1 remediation engine
│   │   ├── remediation_engine.py
│   │   ├── risk_scorer.py
│   │   └── prompt_templates.py
│   ├── api/                         # FastAPI REST layer
│   │   ├── main.py                  # Route definitions
│   │   ├── auth.py                  # Azure AD JWT/JWKS validation
│   │   ├── billing.py               # Stripe billing endpoints
│   │   ├── subscriptions.py         # Per-tenant subscription registry
│   │   ├── onboarding.py            # Azure-only legacy onboarding
│   │   └── onboarding_v1.py         # Multi-cloud onboarding (Azure/AWS/GCP)
│   ├── auth/                        # Customer-credential factory (cross-tenant)
│   ├── billing/                     # Plan catalog, quotas, Stripe service, middleware
│   ├── compliance/                  # Compliance scorecard service
│   ├── finops/                      # FOCUS analytics: coverage, forecasting,
│   │                                #   allocation, budgets, anomalies, unit economics
│   ├── core/                        # Models, enums, config, Cosmos client, observability
│   ├── healing/                     # Drift detector, contract monitor, repair agent
│   ├── onboarding/                  # Cloud-connection + credential-ref + audit repos
│   ├── pipeline/                    # Scan orchestration + AI worker
│   ├── policy/                      # PolicyEngine (NO cloud SDK imports allowed)
│   ├── posture/                     # Posture score aggregation
│   ├── subscriptions/               # Subscription repository + state machine
│   ├── tenants/                     # Tenant-context helpers
│   ├── cli.py                       # `cloudguardiq scan ...` CLI
│   └── __main__.py
├── frontend/                        # React 18 SPA (Vite + Tailwind v4)
│   └── src/
│       ├── pages/                   # Dashboard, Findings, FinOps, Optimization,
│       │                            #   Budgets, AIFix, Compliance, SelfHeal, Settings
│       ├── components/              # dashboard, findings, layout, settings (incl. wizard)
│       ├── api/                     # Axios client with MSAL token interceptor
│       ├── auth/                    # MSAL config + RequireAuth wrapper
│       ├── contexts/  hooks/  lib/  types/
├── infra/                           # Terraform IaC
│   ├── main.tf                      # All Azure resources + RBAC
│   ├── variables.tf  outputs.tf
├── cloudguardiq/api/templates/      # cloudguardiq-reader.json (Deploy-to-Azure ARM,
│                                    #   bundled into the wheel and served anonymously
│                                    #   by GET /subscriptions/onboarding-template.json)
├── tests/                           # 664 pytest tests, 80%+ coverage
├── scripts/                         # Operational scripts (audit, backfill)
├── docs/                            # Design docs (multicloud-onboarding, SaaS plan)
├── function_app.py                  # Azure Functions entry point
├── Dockerfile                       # Backend container image
├── pyproject.toml                   # Python project + optional extras (aws, gcp, dev)
└── .github/workflows/               # ci.yml · infra.yml · deploy.yml
```

---

## 8. Prerequisites

### Local development
- **Python 3.12+**
- **Node.js 20+** and **npm 10+**
- **Azure CLI 2.60+** (`az login` enables `DefaultAzureCredential`)
- **Git 2.40+**
- **Docker Desktop** (optional, for containerized backend runs)
- **Terraform 1.8+** (only if you will provision infrastructure)

### Azure tenant (operator side)
- Azure subscription with **Contributor** access for Terraform apply
- Ability to create an **Azure AD app registration** (multi-tenant)
- One of: **Global Administrator** *or* **Application Administrator** in Entra ID
- (Optional) **Microsoft Partner Network** account for **Publisher Verification**
  before going GA

### Customer tenant (per onboarded customer)
- **Global Administrator** (or Privileged Role Administrator) — for one-time
  admin consent on the multi-tenant app
- **Owner** or **User Access Administrator** on each subscription that will be
  scanned — for assigning the `Reader` role to the CloudGuardIQ service principal

> CloudGuardIQ never writes to customer subscriptions. **`Reader` is the only
> RBAC role required.** AI remediations are rendered as IaC diffs that the
> customer applies themselves.

---

## 9. Quickstart (Local Development)

```bash
# 1. Clone
git clone https://github.com/<your-org>/CloudGuardIQ.git
cd CloudGuardIQ

# 2. Install backend (with dev + optional cloud extras)
pip install -e ".[dev,aws,gcp]"

# 3. Configure environment
cp .env.example .env
# → edit .env with your tenant / Cosmos / OpenAI values (see §12)

# 4. Sign in for DefaultAzureCredential
az login

# 5. Run quality gates
ruff check cloudguardiq/
mypy cloudguardiq/
python -m pytest tests/ -v --cov=cloudguardiq --cov-fail-under=80

# 6. Start the API
uvicorn cloudguardiq.api.main:app --reload
# → http://localhost:8000/docs  (Swagger)
# → http://localhost:8000/redoc

# 7. Start the frontend
cd frontend
npm install
# Create frontend/.env.local with VITE_AZURE_CLIENT_ID, VITE_AZURE_TENANT_ID,
# VITE_REDIRECT_URI, VITE_API_BASE_URL — or generate via Terraform output.
npm run dev
# → http://localhost:3000

# 8. (Optional) Run a one-shot CLI scan
python -m cloudguardiq scan --subscription-id <sub-id> --output json
```

### Demo mode (zero Azure config)

Set `CLOUDGUARDIQ_AUTH_DISABLED=true` to serve canned demo findings on
`/findings`. The UI displays an amber **"Demo mode"** banner across every page.
This is the fastest way to onboard new contributors.

---

## 10. Production Deployment on Azure

### Option A — GitHub Actions (recommended)

1. **Create a CI service principal** with OIDC federated credentials for each
   environment (`dev`, `staging`, `prod`).
2. **Assign roles** to the service principal:

   | Role | Scope | Purpose |
   |------|-------|---------|
   | Contributor | Subscription | Create/manage Azure resources |
   | User Access Administrator | Subscription | Create managed-identity RBAC |
   | Application Administrator | Entra ID | Create app registrations |
   | Storage Blob Data Contributor | tfstate storage | Terraform state via Azure AD |

3. **Configure GitHub secrets**: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
   `AZURE_SUBSCRIPTION_ID`, `TF_STATE_RESOURCE_GROUP`, `TF_STATE_STORAGE_ACCOUNT`,
   plus per-environment `FRONTEND_URL`, `API_URL`, `APP_CLIENT_ID`,
   `SWA_DEPLOYMENT_TOKEN`, optional `ONBOARDING_TEMPLATE_URI`.
4. **Run workflows** in order: `Terraform Infrastructure` (plan → apply) →
   `Deploy` (frontend + backend + functions).

### Option B — Local Terraform

```bash
az login
cd infra

terraform init \
  -backend-config="resource_group_name=tfstate-rg" \
  -backend-config="storage_account_name=<your-tfstate-storage>" \
  -backend-config="container_name=tfstate" \
  -backend-config="key=cloudguardiq.dev.tfstate" \
  -backend-config="use_azuread_auth=true"

terraform plan  -var="environment=dev" -out=tfplan
terraform apply tfplan

# Auto-generate environment files
terraform output -raw backend_env_file  > ../.env
terraform output -raw frontend_env_file > ../frontend/.env.local
```

### What Terraform provisions

| Resource | Name pattern | Purpose |
|----------|-------------|---------|
| Resource Group | `cguardiq-{env}-rg` | Container for all resources |
| Azure AD App (multi-tenant) | `CloudGuardIQ-{env}` | SPA + API auth, customer onboarding |
| Cosmos DB (serverless) | `cguardiq-{env}-cosmos` | NoSQL data store (RBAC-only) |
| Azure OpenAI | `cguardiq-{env}-openai` | GPT-5.1 deployment (RBAC-only) |
| Key Vault | `cguardiq-{env}-kv` | App secrets (e.g. client secret) |
| Service Bus | `cguardiq-{env}-sb` | Async findings queue |
| Container App | `cguardiq-{env}-api` | FastAPI backend |
| Function App | `cguardiq-{env}-func` | Timer scan + AI worker |
| Container Registry | `cguardiq{env}acr` | Backend image storage |
| Static Web App | `cguardiq-{env}-swa` | React frontend |
| Application Insights | `cguardiq-{env}-ai` | APM & tracing |
| Log Analytics | `cguardiq-{env}-law` | Centralized logs |

All managed-identity RBAC assignments (Cosmos Data Contributor, OpenAI User,
Reader on subscription, Service Bus Data Owner/Sender, AcrPull, storage roles)
are auto-provisioned. **Key-based authentication is disabled** on Cosmos DB
and Azure OpenAI.

### Manual one-time setup (cannot be automated)

- **Publisher verification** of the multi-tenant app via Microsoft Partner
  Center. Required before customers outside your tenant can complete consent
  without a security warning.
- **Home-tenant admin consent** on the operator tenant:
  ```bash
  az ad app permission admin-consent --id <azure_ad_client_id>
  ```

---

## 11. Customer Onboarding

The **Multi-Cloud Onboarding Wizard** (Settings → Multi-Cloud Onboarding) walks
operators through enrolling a customer's Azure tenant, AWS account, or GCP
project end-to-end. Target time: **under 15 minutes**.

### 11.1 The 5-step wizard

| # | Step | Primary actor | What happens | API |
|---|------|----------------|--------------|-----|
| 1 | **Choose Provider** | Operator | Pick Azure / AWS / GCP, enter display name + scope (tenant id / account id / project id) | `POST /v1/onboarding/sessions` |
| 2 | **Grant Trust** | Customer admin | Wizard renders one-click **Deploy to Azure** / **CloudFormation Quick-Create** / `gcloud` script with all parameters pre-filled. Customer admin runs it. | `POST /v1/onboarding/sessions/{id}/generate-artifacts` |
| 3 | **Verify** | Operator | Three automated probes: `token_exchange`, `permission_probe`, `scope_discovery`. Auto-advances on success. | `POST /v1/onboarding/sessions/{id}/verify` |
| 4 | **Connect Scopes** | Operator | Pick which discovered subscriptions / accounts / projects to monitor | `POST /v1/onboarding/sessions/{id}/connect` |
| 5 | **Done** | — | Returns `connection_id`; dashboard immediately reflects the new scope | `GET /v1/cloud-connections` |

### 11.2 Roles required per actor

| Actor | Role | Where |
|-------|------|-------|
| CloudGuardIQ Operator | Any signed-in user | Operator tenant (A) |
| Customer Admin | Global Administrator or Privileged Role Admin | Customer tenant (B) — for admin consent |
| Customer Subscription Admin | Owner or User Access Administrator | Each target Azure subscription — for `Reader` RBAC grant |

### 11.3 Azure cross-tenant flow (under the hood)

```
Operator clicks "Onboard"
   ↓
POST /v1/onboarding/sessions  →  session.status = pending_consent + consent_url
   ↓
Customer admin opens consent_url → accepts in Azure AD
   ↓
Azure AD redirects → /settings?consent=callback&tenant=<tid>&admin_consent=True
   ↓
GET /subscriptions/consent-callback  →  TenantConsentRepository.upsert()
   ↓
Session auto-advances → pending_reader
   ↓
Customer admin runs one-click ARM (or `az role assignment create ... --role Reader`)
   ↓
Operator clicks "I Granted Reader Role" → POST /reader-granted
   ↓
POST /discover  →  enumerates visible subscriptions in customer tenant
POST /connect    →  persists under tenant_id = customer_tenant_id
   ↓
Session.status = completed  ·  scan_trigger picks it up on next tick
```

### 11.4 AWS flow

Wizard produces a **CloudFormation Quick-Create URL** that provisions an IAM
role with a `SecurityAudit`-equivalent policy and a trust relationship to the
CloudGuardIQ AWS account. Operator pastes the `RoleArn`; CloudGuardIQ assumes
it via STS for every scan.

### 11.5 GCP flow

Wizard produces a `gcloud` script that grants `roles/viewer` and
`roles/billing.viewer` to a CloudGuardIQ service account on the target project
or folder. CloudGuardIQ authenticates via workload identity federation.

### 11.6 Revocation & re-linking

- Removing the CloudGuardIQ enterprise app or revoking Reader → the next scan
  tick logs `auth_failure` and **auto-disables** the subscription (record is
  retained, findings preserved).
- After consent + RBAC are restored: `PATCH /subscriptions/{id}` with
  `{ "state": "Enabled" }` to resume scans.
- For full server-side revocation: `TenantConsentRepository.revoke(<tid>)` —
  subsequent `POST /subscriptions` calls for that tenant return
  `400 consent_required`.

### 11.7 Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `400 invalid_tenant_id` | Bad GUID | Re-enter and restart session |
| Stuck on `pending_consent` | Consent not yet accepted | Open `consent_url`, accept, click **Refresh Status** |
| `400 consent_failed` in callback | Admin declined / error in callback | Re-run consent |
| `400 access_denied` / `reader_role_required` | RBAC missing or not propagated | Grant Reader, wait up to 5 min, retry discovery |
| Session start returns 500/503 | Onboarding container/repo not configured | Re-apply Terraform |

### 11.8 Manual Reader grant (customer tenant shell)

```bash
# One-time: discover the object id of the cgiq enterprise app in tenant B
CGIQ_OBJECT_ID=$(az ad sp show --id <cgiq-client-id> --query id -o tsv)

# Grant Reader on each subscription the customer wants to scan
az role assignment create \
  --assignee $CGIQ_OBJECT_ID \
  --role Reader \
  --scope /subscriptions/<sub-guid>
```

Allow up to **5 minutes** for the role assignment to propagate before discovery.

---

## 12. Configuration Reference

### 12.1 Backend environment variables (Python)

Variables prefixed `CLOUDGUARDIQ_` are loaded by **pydantic-settings**.

#### Core

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_CLIENT_ID` | Yes | App registration client ID |
| `AZURE_TENANT_ID` | Yes | Operator (home) tenant ID |
| `AZURE_SUBSCRIPTION_ID` | No | **Dev / CLI only.** Prod uses per-tenant registry. |
| `CLOUDGUARDIQ_COSMOS_ENDPOINT` | Yes | Cosmos DB account endpoint |
| `CLOUDGUARDIQ_AZURE_OPENAI_ENDPOINT` | Yes | Azure OpenAI endpoint |
| `CLOUDGUARDIQ_AZURE_OPENAI_DEPLOYMENT` | No | Model deployment name (default `gpt-5.1`) |
| `CLOUDGUARDIQ_AZURE_TENANT_ID` | Yes | Tenant ID for JWT validation |
| `CLOUDGUARDIQ_AZURE_CLIENT_ID` | Yes | Client ID for JWT audience validation |
| `SERVICE_BUS_CONNECTION__fullyQualifiedNamespace` | No | Service Bus FQDN (managed identity) |
| `KEY_VAULT_URL` | No | Key Vault URI |
| `CLOUDGUARDIQ_AUTH_DISABLED` | No | `true` enables demo mode |

#### Cross-tenant / onboarding

| Variable | Required | Description |
|----------|----------|-------------|
| `CLOUDGUARDIQ_AZURE_CLIENT_SECRET` | Cross-tenant | Secret for `CustomerCredentialFactory` |
| `CLOUDGUARDIQ_AZURE_CERTIFICATE_PATH` | Cross-tenant | PFX/PEM cert (preferred over secret) |
| `CLOUDGUARDIQ_CONSENT_REDIRECT_URI` | Cross-tenant | Reply URL for admin-consent callback |
| `CLOUDGUARDIQ_PUBLIC_API_BASE_URL` | No | Public API URL — enables ARM `parameters_uri` prefill and the bundled `onboarding-template.json` route |
| `CLOUDGUARDIQ_ONBOARDING_TEMPLATE_URI` | No | Override the ARM template URL. When empty, the API serves the template it ships with at `{CLOUDGUARDIQ_PUBLIC_API_BASE_URL}/subscriptions/onboarding-template.json` so the GitHub repo can stay private |

#### Cosmos container overrides

| Variable | Default |
|----------|---------|
| `CLOUDGUARDIQ_COSMOS_CONTAINER_SUBSCRIPTIONS` | `subscriptions` |
| `CLOUDGUARDIQ_COSMOS_CONTAINER_TENANT_CONSENTS` | `tenant_consents` |
| `CLOUDGUARDIQ_COSMOS_CONTAINER_ONBOARDING_SESSIONS` | `onboarding_sessions` |

#### Billing / Stripe

| Variable | Description |
|----------|-------------|
| `STRIPE_API_KEY` | Stripe secret key |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret |
| `STRIPE_PRICE_STARTER` / `STRIPE_PRICE_ENTERPRISE` | Stripe Price IDs per plan |

### 12.2 Frontend environment variables (Vite)

| Variable | Description |
|----------|-------------|
| `VITE_AZURE_CLIENT_ID` | CloudGuardIQ-dev app client ID (= `APP_CLIENT_ID` secret) |
| `VITE_AZURE_TENANT_ID` | `common` for multi-tenant, or specific tenant ID |
| `VITE_REDIRECT_URI` | MSAL redirect URI (default `http://localhost:3000`) |
| `VITE_API_BASE_URL` | Backend URL (default `/api`) |

### 12.3 Terraform input variables (`infra/variables.tf`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `prefix` | string | `cguardiq` | Resource name prefix |
| `environment` | string | `dev` | `dev` / `staging` / `prod` |
| `location` | string | `eastus` | Primary Azure region |
| `openai_location` | string | `eastus2` | Region for OpenAI |
| `swa_location` | string | `eastus2` | Region for Static Web App |
| `openai_capacity` | number | `10` | TPM capacity (thousands) |
| `api_container_image` | string | hello-world | Initial backend image |
| `frontend_redirect_uris` | list(string) | `["http://localhost:3000"]` | Extra MSAL redirect URIs |
| `consent_redirect_uris` | list(string) | localhost callback | Extra admin-consent Reply URLs |
| `onboarding_template_uri` | string | `""` | Public ARM template URL (Deploy-to-Azure) |

### 12.4 Terraform outputs (`infra/outputs.tf`)

`resource_group_name`, `azure_ad_client_id`, `azure_ad_tenant_id`,
`cosmosdb_endpoint`, `openai_endpoint`, `key_vault_uri`,
`servicebus_connection_string`, `appinsights_connection_string`, `api_url`,
`function_app_name`, `frontend_url`, `acr_name`, `acr_login_server`,
`backend_env_file`, `frontend_env_file`.

---

## 13. REST API Reference

OpenAPI 3 spec is auto-generated at `/docs` (Swagger UI) and `/redoc`.
All endpoints except `/health`, `/config`, `/billing/plans`, and
`/subscriptions/onboarding-parameters/{id}` require a Bearer JWT from Azure AD.

### Public

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness probe |
| GET | `/config` | Client config (`demo_mode`, `client_id`, `version`) |
| GET | `/billing/plans` | Public plan catalog |

### Scans

| Method | Path | Description |
|--------|------|-------------|
| POST | `/scan` | Synchronous scan |
| POST | `/scan/trigger` | Queue async scan (Service Bus) |
| GET | `/scan/{scan_id}/status` | Scan result by ID |

### Findings & remediation

| Method | Path | Description |
|--------|------|-------------|
| GET | `/findings` | List remediation cards sorted by priority |
| GET | `/findings/{id}` | Single remediation card |
| GET | `/findings/{id}/terraform` | Terraform fix as `text/plain` |
| POST | `/findings/{id}/generate-remediation` | Re-run GPT-5.1 for a finding (AI-quota gated) |

### Subscriptions (Azure, per-tenant)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/subscriptions` | List subscriptions for caller tenant |
| POST | `/subscriptions` | Link a subscription (`402` if cap exceeded) |
| PATCH | `/subscriptions/{id}` | Rename or enable/disable |
| DELETE | `/subscriptions/{id}` | Unlink (findings retained per retention policy) |
| GET | `/subscriptions/discover` | Enumerate subscriptions visible to CloudGuardIQ in customer tenant |
| GET | `/subscriptions/consent-url` | Build Azure AD admin-consent URL |
| GET | `/subscriptions/consent-callback` | Record consent after Azure AD redirect |
| GET | `/subscriptions/onboarding-template` | One-click Deploy-to-Azure URL |
| GET | `/subscriptions/onboarding-parameters/{principal_id}` | Public ARM `deploymentParameters.json` |
| POST | `/subscriptions/onboarding-sessions` | Start an Azure-only onboarding session |
| GET | `/subscriptions/onboarding-sessions/{id}` | Read session status |
| POST | `/subscriptions/onboarding-sessions/{id}/reader-granted` | Confirm RBAC grant |
| POST | `/subscriptions/onboarding-sessions/{id}/discover` | Enumerate customer subscriptions |
| POST | `/subscriptions/onboarding-sessions/{id}/connect` | Link selected subscriptions |
| GET | `/onboarding/info` | CloudGuardIQ SP object id + manual `az` template |

### Multi-cloud onboarding (V1)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/onboarding/sessions` | Create session (Azure / AWS / GCP) |
| GET | `/v1/onboarding/sessions/{id}` | Read session |
| POST | `/v1/onboarding/sessions/{id}/generate-artifacts` | Render provider-specific deploy artifacts |
| POST | `/v1/onboarding/sessions/{id}/verify` | Run `token_exchange` + `permission_probe` + `scope_discovery` |
| POST | `/v1/onboarding/sessions/{id}/connect` | Persist selected scopes |
| GET | `/v1/cloud-connections` | List all cloud connections |
| POST | `/v1/cloud-connections/{id}/refresh` | Re-verify connection |
| DELETE | `/v1/cloud-connections/{id}` | Disconnect |

### Billing

| Method | Path | Description |
|--------|------|-------------|
| GET | `/billing/status` | Current tier, Stripe customer, usage |
| POST | `/billing/checkout` | Create a Stripe checkout session |
| POST | `/billing/webhook` | Stripe webhook handler |

### Compliance & posture

| Method | Path | Description |
|--------|------|-------------|
| GET | `/compliance/scorecard` | Per-framework scorecard |
| GET | `/posture/score` | Aggregated posture score (0–100) |

---

## 14. Security & Compliance

### 14.1 Authentication & authorization

- **Zero shared secrets** between Azure services. All intra-Azure calls use
  Managed Identity via `DefaultAzureCredential`.
- **CI/CD** authenticates to Azure via **OIDC workload identity federation**.
- **Frontend → Backend**: MSAL-issued Azure AD token, validated server-side
  against Azure AD JWKS keys.
- **Cross-tenant**: `CustomerCredentialFactory` issues per-tenant
  `ClientCertificateCredential` (preferred) or `ClientSecretCredential` for
  customer-tenant API calls. The secret/cert lives only in Key Vault.

### 14.2 Tenant isolation

- Every `ResourceSnapshot`, `FindingResult`, `RemediationCard`, scan result,
  and subscription record carries `tenant_id`.
- All Cosmos queries are filtered by `tenant_id` extracted from the caller's
  validated JWT `tid` claim. **Cross-tenant reads are impossible** even with
  guessed IDs.
- `/scan`, `/findings`, and `/subscriptions/*` return `403 subscription_not_linked`
  when a tenant requests data outside their scope.

### 14.3 Data protection

- **Cosmos DB**: serverless, RBAC-only (`local_authentication_disabled = true`),
  encrypted at rest with Microsoft-managed keys (CMK supported via Key Vault).
- **Azure OpenAI**: RBAC-only (`local_auth_enabled = false`), no prompts or
  completions retained on Microsoft side beyond service-default windows.
- **Secrets**: Key Vault for app secrets, GitHub OIDC for CI — no long-lived
  credentials in pipelines or env vars.
- **PII**: CloudGuardIQ does not collect end-user PII. Only Azure resource
  metadata and the operator's Azure AD `oid` / `tid` / `email` are stored.

### 14.4 OWASP Top 10 alignment

- **A01 Broken Access Control** — tenant-scoped queries, JWT validation, RBAC
- **A02 Cryptographic Failures** — TLS everywhere, RBAC-only data plane, no shared keys
- **A03 Injection** — Pydantic v2 validation at every boundary, parameterized Cosmos queries
- **A05 Security Misconfiguration** — Terraform-codified configuration, ruff/mypy gates
- **A07 Identification & Auth Failures** — MSAL + Azure AD, JWKS validation, no password storage
- **A09 Logging & Monitoring Failures** — App Insights tracing on every request + worker

### 14.5 Compliance frameworks mapped

CIS Microsoft Azure / AWS / GCP Foundations · NIST SP 800-53 Rev. 5 ·
ISO/IEC 27001:2022 · PCI-DSS v4.0 · SOC 2 (Type II) · HIPAA Security Rule.

Each `FindingResult` carries `compliance_frameworks: list[str]` with prefixed
control IDs (e.g. `["CIS_AWS_2.2.1", "NIST_SC-28", "ISO_27001_A.8.24",
"PCI_DSS_3.5.1", "SOC2_CC6.1", "HIPAA_164.312(a)(2)(iv)"]`) so auditors can
pivot directly from a finding to a specific control. Framework registry and
prefix matching live in [`cloudguardiq/compliance/scorecard.py`](cloudguardiq/compliance/scorecard.py).

---

## 15. Observability & Operations

| Capability | Implementation |
|------------|----------------|
| Distributed tracing | Application Insights — API → Service Bus → Worker |
| Structured logging | Python `logging` module (never `print()`) routed to Log Analytics |
| Metrics | App Insights custom metrics: scan duration, AI tokens, quota hits, queue depth |
| Health probes | `GET /health` (liveness) — wired into Container Apps probes |
| Alerting | Azure Monitor alerts on 5xx rate, queue depth, AI quota saturation |
| Audit log | Per-tenant `audit_events` Cosmos container (consent, RBAC, billing changes) |
| Dashboards | App Insights workbooks (importable JSON in `docs/workbooks/`) |

---

## 16. Testing & Quality

- **664 tests** across adapters, API, policy engine, AI remediation, pipeline,
  healing, billing, onboarding, compliance scorecard, and tenant isolation.
- **Minimum coverage: 80 %** (enforced in CI).
- All external services (Azure SDK, OpenAI, Cosmos, Stripe) are **mocked** in
  tests — no live network calls in the test suite.
- **Strict typing**: mypy passes on `cloudguardiq/` with `disallow_untyped_defs`.
- **Lint**: ruff with project-defined ruleset in [ruff.toml](ruff.toml).

```bash
# Full quality gate (mirrors CI)
ruff check cloudguardiq/
mypy cloudguardiq/
python -m pytest tests/ -v --cov=cloudguardiq --cov-fail-under=80

# Run a single suite
python -m pytest tests/test_ai_remediation.py -v
python -m pytest tests/adapters/ -k "azure"
```

---

## 17. CI/CD

GitHub Actions workflows in [`.github/workflows/`](.github/workflows/):

| Workflow | File | Trigger | Purpose |
|----------|------|---------|---------|
| **CI — Lint / Type / Test** | `ci.yml` | `workflow_dispatch` | ruff + mypy + pytest (≥ 80 % cov) + `terraform validate / fmt` |
| **Terraform Infrastructure** | `infra.yml` | `workflow_dispatch` (env, action) | OIDC login → init → fmt → validate → plan → apply |
| **Deploy** | `deploy.yml` | `workflow_dispatch` (env) | Build & ship frontend (SWA), backend (ACR → Container App), and functions |

All workflows authenticate to Azure via **OIDC workload identity federation** —
no stored Azure credentials in GitHub.

---

## 18. Roadmap

| Phase | Status | Highlights |
|-------|--------|------------|
| **Phase 1 — Azure CSPM + FinOps + AI** | ✅ Shipped | 52 rules, GPT-5.1 remediation, single-tenant |
| **Phase 2 — Multi-tenant SaaS** | ✅ Shipped | Tenant isolation, Stripe billing, quota enforcement |
| **Phase 3 — Cross-tenant onboarding** | ✅ Shipped | Consent wizard, customer-credential factory, auto-disable |
| **Phase 4 — Multi-cloud (AWS / GCP)** | 🟡 In progress | AWS rule pack live, GCP early access, unified V1 onboarding |
| **Phase 5 — Self-healing GA** | 🟡 In progress | Drift detector & contract monitor live; auto-repair gated to Enterprise |
| **FinOps “Operate” maturity** | ✅ Shipped | FOCUS ledger, native recommenders, commitment coverage, forecasting, allocation, budgets, anomalies, unit economics |
| **Phase 6 — SIEM / SOAR integrations** | ⏳ Planned | Splunk, Sentinel, ServiceNow, PagerDuty |
| **Phase 7 — Custom policy SDK** | ⏳ Planned | Python + Rego DSL for customer-authored rules |

See [docs/saas-phased-plan.md](docs/saas-phased-plan.md) and
[docs/saas-decisions.md](docs/saas-decisions.md) for architectural decision
records.

---

## 19. Support

| Channel | Where | When |
|---------|-------|------|
| **Documentation** | [`docs/`](docs/) directory + `/docs` Swagger | Always |
| **In-product help** | Settings → Help & Onboarding | All plans |
| **Community support** | GitHub Discussions | Free / Starter |
| **Email support** | support@cloudguardiq.com | Starter (24h SLO) |
| **Priority support** | support@cloudguardiq.com + Slack Connect | Enterprise (4h SLO) |
| **Security disclosures** | security@cloudguardiq.com (PGP key in `SECURITY.md`) | All plans |

---

## 20. License

CloudGuardIQ is released under the **Apache License, Version 2.0** — an
OSI-approved permissive open-source license that allows commercial use,
modification, distribution, patent grant, and private use.

```
Copyright 2026 Sandip Patel and CloudGuardIQ contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

The full license text is available in [LICENSE](LICENSE).

### Author & original contribution

CloudGuardIQ is the original work of **Sandip Patel**. The architecture,
tiered data-source strategy, cross-tenant onboarding model, GPT-5.1
structured-output remediation pipeline, multi-cloud rule packs, and
quota-aware SaaS billing layer are independent contributions authored
for this project.

### Contributing

Contributions are welcome under the Apache 2.0 license. By submitting a pull
request you agree that your contribution is licensed under the same terms.
See [CONTRIBUTING.md](CONTRIBUTING.md) when present, or open an issue to
discuss substantial changes first.

### Trademarks

"CloudGuardIQ" and the CloudGuardIQ logo are trademarks of the author.
The Apache 2.0 license grants rights to the source code but does not grant
permission to use these trademarks. "Azure", "AWS", "GCP", "Microsoft",
and other product names are trademarks of their respective owners.

---

<div align="center">

**CloudGuardIQ** · Built on Azure · Powered by GPT-5.1 · Open source under Apache 2.0

</div>
