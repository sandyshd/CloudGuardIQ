# CloudGuardIQ — FinOps Cost Flow

> **Audience:** Executive / C-Suite + Engineering
> **Purpose:** Explain exactly how CloudGuardIQ turns a customer's live cloud
> bill into trustworthy per-resource cost, waste findings, and rightsizing
> savings — across Azure, AWS, and GCP — end to end.

---

## 1. The Big Picture (60-second version)

Security tells you what is *risky*. FinOps tells you what is *wasteful*.
CloudGuardIQ attaches a **real dollar figure** to every resource on every scan,
so a single pass surfaces cost waste right next to security risk. It does this in
four moves:

1. **Resolve** a clean billing window (one closed calendar month — no partial-
   month skew).
2. **Price** every resource — first from the customer's **actual bill**, falling
   back to the **public list price** when the bill is not yet available.
3. **Estimate savings** — rightsizing deltas computed from *live* prices, not
   flat guesses.
4. **Stamp & surface** — tag each resource with its data tier and feed the FinOps
   rule engine, the dashboard, and AI remediation.

```mermaid
flowchart LR
    A["Customer Cloud Bill<br/>(Azure / AWS / GCP)"] --> B["1 Resolve<br/>Billing window"]
    B --> C["2 Price<br/>Actual then List"]
    C --> D["3 Estimate<br/>Rightsizing savings"]
    D --> E["4 Stamp + Store<br/>data_tier + waste $"]
    E --> F["Dashboard +<br/>AI Remediation"]

    style A fill:#1f2937,color:#fff
    style B fill:#2563eb,color:#fff
    style C fill:#7c3aed,color:#fff
    style D fill:#0891b2,color:#fff
    style E fill:#16a34a,color:#fff
    style F fill:#ea580c,color:#fff
```

**Key business design principle:** cost is **enrichment, never a hard
dependency**. If a billing or pricing API is throttled, unauthorized, or down,
the lookup degrades to an empty result and the scan still completes — no crash,
no blank dashboard.

### What shipped — the FinOps maturity stack (5 phases)

CloudGuardIQ's FinOps capability landed in five incremental phases. The first two
sit inside the **scan pipeline** (per-resource cost + waste). The last three are a
pure **analytics layer** over a normalized cost ledger (FOCUS), exposed as its own
`/finops/*` API and UI — none of it depends on Microsoft Defender for Cloud.

| Phase | Theme | What it added | Where it lives |
|-------|-------|---------------|----------------|
| **1 — FOCUS ingestion** | A common cost ledger | FinOps-FOCUS-normalized billing rows for Azure/AWS/GCP, the `CostProvider` seam, the `focus_costs` container | `billing/cost_provider.py`, `core/models.py` (`FocusCostRecord`) |
| **2 — Utilization + rightsizing** | Idle / oversized detection | Utilization metrics providers + idle/rightsizing activation feeding the FinOps rules | `billing/*_metrics_provider.py`, `adapters/rules/azure/finops.py` |
| **3 — Native recommenders** | The cloud's own advice | Azure Advisor / AWS / GCP recommender adapters merged into the scan as **DIRECT** savings | `adapters/recommenders/*` |
| **4 — Coverage + forecasting** | Commitments & trend | Commitment coverage/utilization analysis and day-of-week spend forecasting | `finops/commitments.py`, `finops/forecasting.py` |
| **5 — Operate** | Allocation, budgets, anomalies, unit economics | Showback/chargeback + tag coverage, budgets (actual & forecast vs target), statistical anomaly alerting, cost-per-unit | `finops/allocation.py`, `finops/budgets.py`, `finops/anomaly.py`, `finops/unit_economics.py` |

> **Sections 2–7** below cover the in-pipeline cost flow (phases 1–2). **Sections
> 8–14** cover the analytics layer (phases 3–5).

---

## 2. The CostProvider Seam — One Contract, Three Clouds

Exactly like `AdapterBase` is the only thing allowed to touch cloud *inventory*
APIs, **`CostProvider` is the only thing allowed to touch cloud *billing /
pricing* APIs.** Every cloud implements the same two-method contract, so the
adapters, rules, and dashboard stay provider-agnostic.

```mermaid
flowchart TD
    CP["CostProvider (abstract)<br/>get_actual_cost() / get_list_price()"]

    CP --> AZ["AzureCostProvider"]
    CP --> AWS["AwsCostProvider"]
    CP --> GCP["GcpCostProvider"]

    AZ --> AZ1["Actual: Cost Management<br/>(query.usage / ActualCost)"]
    AZ --> AZ2["List: Retail Prices catalog<br/>(PricingService cache)"]

    AWS --> AWS1["Actual: Cost Explorer<br/>(get_cost_and_usage)"]
    AWS --> AWS2["List: Price List Query API"]

    GCP --> GCP1["Actual: BigQuery billing export<br/>(SUM cost by resource.name)"]
    GCP --> GCP2["List: Cloud Billing Catalog<br/>(list_services to list_skus)"]

    style CP fill:#1e3a8a,color:#fff
    style AZ fill:#2563eb,color:#fff
    style AWS fill:#b45309,color:#fff
    style GCP fill:#0e7490,color:#fff
    style AZ1 fill:#6d28d9,color:#fff
    style AZ2 fill:#6d28d9,color:#fff
    style AWS1 fill:#6d28d9,color:#fff
    style AWS2 fill:#6d28d9,color:#fff
    style GCP1 fill:#6d28d9,color:#fff
    style GCP2 fill:#6d28d9,color:#fff
```

The base class (`cloudguardiq/billing/cost_provider.py`) owns all the
cross-cutting behaviour so no provider re-implements it:

| Public method | Returns | On empty input | On any failure |
|---------------|---------|----------------|----------------|
| `get_actual_cost(ids, window=...)` | `{resource_id -> monthly USD}` | `{}` (short-circuit) | `{}` + warning log |
| `get_list_price(sku, region, default=...)` | monthly USD `float` | — | `default` / `0.0` + warning log |

> Resource ids are lower-cased on the way out so every cloud compares cleanly.
> Each subclass only implements the two protected `_fetch_*` template methods.

---

## 3. Two Price Signals, Two Data Tiers

CloudGuardIQ deliberately distinguishes **what was actually billed** from **what
the catalog says a SKU costs**. They map onto the project's data-tier model so
the dashboard can show how trustworthy each number is.

```mermaid
flowchart TD
    Need["Need cost for a resource"] --> Actual{"Actual billed cost<br/>available?"}
    Actual -- "Yes" --> T2["Use EffectiveCost<br/>stamp data_tier = TIER2_ENRICHED"]
    Actual -- "No (new resource,<br/>export not ready,<br/>API denied)" --> List{"List price<br/>resolvable?"}
    List -- "Yes" --> T1["Use catalog price<br/>stamp data_tier = TIER1_NATIVE"]
    List -- "No" --> Zero["cost_monthly = 0.0<br/>(never crash)"]

    style Need fill:#1f2937,color:#fff
    style Actual fill:#b45309,color:#fff
    style List fill:#b45309,color:#fff
    style T2 fill:#6d28d9,color:#fff
    style T1 fill:#1e3a8a,color:#fff
    style Zero fill:#16a34a,color:#fff
```

| Signal | Source per cloud | Meaning | Data tier |
|--------|------------------|---------|-----------|
| **Actual cost** | Azure Cost Management · AWS Cost Explorer · GCP BigQuery export | Real billed / effective spend — authoritative | **Tier 2 — Enriched** |
| **List price** | Azure Retail Prices · AWS Price List · GCP Cloud Billing Catalog | Public catalog price — strong lower bound | **Tier 1 — Native** |

> **No dollar amount is ever hardcoded** in an adapter or rule. Every figure is
> pulled live from a billing or pricing API. The bundled static catalog exists
> only as a **logged, offline last resort** inside the providers.

---

## 4. The Billing Window — Apples-to-Apples Across Clouds

Every cost figure is anchored to a precise, well-defined billing window so the
numbers mean exactly the same thing on Azure, AWS, and GCP. `CostWindow` is the
**single source of truth** for date math, shared by all three clouds, so spend is
measured over the same period everywhere and is directly comparable.

```mermaid
flowchart LR
    R["Request cost"] --> W{"Which window?"}
    W -- "default" --> M["last_full_month<br/>closed calendar month<br/>(no partial-month skew)"]
    W -- "dashboards" --> D["trailing_30d<br/>rolling 30-day view"]
    M --> Q["start / end / days<br/>handed to each provider query"]
    D --> Q

    style R fill:#1f2937,color:#fff
    style W fill:#b45309,color:#fff
    style M fill:#2563eb,color:#fff
    style D fill:#0891b2,color:#fff
    style Q fill:#16a34a,color:#fff
```

- Hourly meters (VMs, public IPs, disks priced per-GiB) are converted to monthly
  with the shared constant **`HOURS_PER_MONTH = 730.0`**, identical across clouds.
- The window is `frozen` and resolved from an injectable `now`, so tests are
  deterministic.

---

## 5. How Each Cloud Computes Cost

All three providers share the same shape: **actual cost grouped by resource id**,
**list price decoded from a logical SKU key**, and **graceful degradation** on
every external call.

```mermaid
flowchart TD
    subgraph AZURE["AZURE — AzureCostProvider"]
        AZa["Actual: Cost Management query.usage,<br/>ActualCost grouped by ResourceId.<br/>429 retried with backoff."]
        AZl["List: Retail Prices via PricingService cache."]
        AZr["Rightsizing: live price delta<br/>current VM SKU minus recommended SKU."]
    end
    subgraph AWSP["AWS — AwsCostProvider"]
        AWa["Actual: Cost Explorer get_cost_and_usage,<br/>MONTHLY AmortizedCost grouped by RESOURCE_ID<br/>(End-exclusive window)."]
        AWl["List: Price List Query API.<br/>SKUs: ebs:type:size, ec2:instanceType, eip:idle."]
        AWr["Rightsizing: next-size-down map x live EC2 price."]
    end
    subgraph GCPP["GCP — GcpCostProvider"]
        GCa["Actual: BigQuery billing export,<br/>SUM(cost) by resource.name<br/>(table from GCG_GCP_BILLING_EXPORT_TABLE)."]
        GCl["List: Cloud Billing Catalog list_services to<br/>list_skus, units + nanos to monthly.<br/>SKUs: pd:type:size, gce:machineType."]
        GCr["Rightsizing: next-size-down map x live GCE price."]
    end

    style AZURE fill:#1e3a8a,color:#fff
    style AWSP fill:#b45309,color:#fff
    style GCPP fill:#0e7490,color:#fff
    style AZa fill:#2563eb,color:#fff
    style AZl fill:#2563eb,color:#fff
    style AZr fill:#2563eb,color:#fff
    style AWa fill:#92400e,color:#fff
    style AWl fill:#92400e,color:#fff
    style AWr fill:#92400e,color:#fff
    style GCa fill:#155e75,color:#fff
    style GCl fill:#155e75,color:#fff
    style GCr fill:#155e75,color:#fff
```

| Concern | Azure | AWS | GCP |
|---------|-------|-----|-----|
| **Actual cost API** | Cost Management `query.usage` (ActualCost) | Cost Explorer `get_cost_and_usage` | BigQuery billing export |
| **Group key** | `ResourceId` | `RESOURCE_ID` | `resource.name` |
| **List price API** | Retail Prices (PricingService) | Price List Query API | Cloud Billing Catalog |
| **Compute SKU key** | VM SKU | `ec2:<instanceType>` | `gce:<machineType>` |
| **Disk SKU key** | disk SKU | `ebs:<type>:<gb>` | `pd:<type>:<gb>` |
| **Idle / misc** | — | `eip:idle` | — |
| **Throttling** | 429 retried w/ backoff | guarded executor → `[]` | guarded query → `{}` |

---

## 6. Where Cost Attaches to a Scan — `_enrich_costs`

After inventory is discovered, each adapter runs a single `_enrich_costs` pass
over the cost-relevant resource types (VMs / instances and disks). This is the
one place the adapter calls its `CostProvider`.

```mermaid
flowchart TD
    Inv["Discovered snapshots"] --> Filter["Select FINOPS_COST_TYPES<br/>(compute instances + disks)"]
    Filter --> Bulk["get_actual_cost(resource_ids)<br/>one bulk billing call"]
    Bulk --> Has{"Actual cost<br/>for this resource?"}

    Has -- "Yes" --> SetA["cost_monthly = actual<br/>data_tier = TIER2_ENRICHED"]
    Has -- "No" --> Sku["Decode logical SKU<br/>_list_price_sku(snap)"]
    Sku --> ListP["get_list_price(sku, region)"]
    ListP --> SetL["cost_monthly = list price<br/>data_tier = TIER1_NATIVE"]

    SetA --> RS{"Is it a compute<br/>instance?"}
    SetL --> RS
    RS -- "Yes" --> Save2["Stamp config[rightsizing_savings_monthly_usd]<br/>= live price delta"]
    RS -- "No" --> Done
    Save2 --> Done(["Enriched snapshot<br/>ready for rules + dashboard"])

    style Inv fill:#1f2937,color:#fff
    style Filter fill:#2563eb,color:#fff
    style Bulk fill:#7c3aed,color:#fff
    style Has fill:#b45309,color:#fff
    style SetA fill:#6d28d9,color:#fff
    style SetL fill:#1e3a8a,color:#fff
    style RS fill:#b45309,color:#fff
    style Save2 fill:#0891b2,color:#fff
    style Done fill:#16a34a,color:#fff
```

- **Actual cost is preferred**; list price is the fallback so a brand-new
  resource (no billing history yet) still gets a credible number.
- Rightsizing savings land in `config["rightsizing_savings_monthly_usd"]`, which
  the FinOps rules read to produce waste findings and the dashboard sums into
  "waste $ identified".

---

## 7. Rightsizing — Savings From Live Price Deltas

Rightsizing savings are grounded in real catalog economics. Each provider
computes savings as the **actual price difference** between the current SKU and
the recommended next-size-down SKU, both priced live — a defensible, finance-ready
number rather than a rule-of-thumb estimate.

$$ \text{Savings}_{\text{monthly}} = \text{Price}(\text{current SKU}) - \text{Price}(\text{next size down}) $$

```mermaid
flowchart LR
    Cur["Current instance<br/>(e.g. n1-standard-4)"] --> Map["Structural next-size-down map<br/>(family-aware)"]
    Map --> Down["Recommended SKU<br/>(e.g. n1-standard-2)"]
    Cur --> P1["Live price(current)"]
    Down --> P2["Live price(down)"]
    P1 --> Delta["Delta = P1 - P2"]
    P2 --> Delta
    Delta --> Out["rightsizing_savings_monthly_usd"]

    style Cur fill:#1f2937,color:#fff
    style Map fill:#b45309,color:#fff
    style Down fill:#2563eb,color:#fff
    style P1 fill:#7c3aed,color:#fff
    style P2 fill:#7c3aed,color:#fff
    style Delta fill:#0891b2,color:#fff
    style Out fill:#16a34a,color:#fff
```

| Cloud | Recommendation map | Priced via |
|-------|--------------------|-----------|
| **Azure** | VM SKU → smaller VM SKU | Retail Prices delta |
| **AWS** | `_EC2_NEXT_SIZE_DOWN` (t3 / m5 / c5 / r5 families) | Price List delta |
| **GCP** | `_GCE_NEXT_SIZE_DOWN` (n1 / n2 / e2 / c2 families) | Catalog delta |

> If either price is unavailable the savings simply isn't stamped — the resource
> still keeps its cost. Degradation never produces a misleading number.

---

## 8. Native Recommenders — DIRECT Savings From the Cloud's Own Advisor

Phases 1–2 derive savings from **our** price math (sections 6–7). Phase 3 also
ingests the cloud provider's **own** optimization advice — Azure Advisor, AWS
Cost Optimization Hub / Compute Optimizer, GCP Recommender — and merges those
findings into the same scan. Because the number comes straight from the
provider, it is stamped as a **DIRECT** savings signal (highest confidence),
versus the **ESTIMATED** numbers our own heuristics produce.

```mermaid
flowchart LR
    Scan["Unified scan pipeline"] --> Own["Our findings<br/>(rules + rightsizing)<br/>method = ESTIMATED"]
    Scan --> Rec["Native recommender adapter<br/>(Advisor / AWS / GCP)<br/>method = DIRECT"]
    Own --> Merge["Merge by resource + rule"]
    Rec --> Merge
    Merge --> Out["Findings ranked by<br/>confidence + impact"]

    style Scan fill:#1f2937,color:#fff
    style Own fill:#2563eb,color:#fff
    style Rec fill:#16a34a,color:#fff
    style Merge fill:#7c3aed,color:#fff
    style Out fill:#ea580c,color:#fff
```

Every `FindingResult` carries two FinOps trust fields so the dashboard and
finance can weight a number by how it was derived:

| `finops_method` | Meaning | `finops_confidence` |
|-----------------|---------|---------------------|
| `DIRECT` | Provider's own recommendation / billed figure | HIGH |
| `ESTIMATED` | CloudGuardIQ heuristic (rightsizing delta, anomaly excess) | MEDIUM |
| `NONE` | Governance finding, no dollar claim | LOW |

> Recommender APIs are wrapped like every other external call — an Advisor
> outage drops the DIRECT enrichment and the scan keeps our ESTIMATED findings.

---

## 9. The FOCUS Ledger — One Normalized Cost Table for Every Cloud

The analytics layer never queries a cloud directly. It reads one normalized
table: **`FocusCostRecord`** rows (FinOps Open Cost & Usage Specification)
persisted in the `focus_costs` Cosmos container, partitioned by `/tenant_id`.
Azure, AWS, and GCP bills are all flattened into the same shape, so allocation,
budgets, forecasting, and anomalies are written **once** and work for all three.

```mermaid
flowchart LR
    AZ["Azure Cost Mgmt"] --> N["Normalize to FOCUS"]
    AWS["AWS CUR / Cost Explorer"] --> N
    GCP["GCP BigQuery export"] --> N
    N --> Ledger[("focus_costs<br/>partition: /tenant_id")]
    Ledger --> Analytics["finops/* analytics<br/>(pure functions)"]

    style AZ fill:#2563eb,color:#fff
    style AWS fill:#b45309,color:#fff
    style GCP fill:#0e7490,color:#fff
    style N fill:#7c3aed,color:#fff
    style Ledger fill:#1e3a8a,color:#fff
    style Analytics fill:#16a34a,color:#fff
```

Key fields used downstream: `tenant_id`, `sub_account_id` (Azure sub / AWS
account / GCP project), `billing_period`, `charge_period_start`, `charge_category`
(Usage / Purchase / …), `effective_cost`, `service_name` / `service_category`,
`commitment_discount_id`, and `tags` (the allocation dimensions). Every analytics
function in `cloudguardiq/finops/` is a **pure function over these rows** — no
cloud SDK, no I/O — which is why they are fully unit-tested and degrade to empty
results when the ledger is unavailable.

---

## 10. Commitment Coverage & Utilization (Phase 4)

`finops/commitments.py` answers two reservation questions from FOCUS rows:
**coverage** ("what share of eligible compute is covered by a Reservation /
Savings Plan / CUD?") and **utilization** ("of what we committed to and paid for,
how much did we actually use?").

```mermaid
flowchart TD
    Rows["FOCUS rows"] --> Split{"charge_category"}
    Split -- "Purchase + commitment id" --> Comm["Committed spend"]
    Split -- "Usage, no commitment" --> OnD["On-demand eligible spend"]
    Comm --> Cov["coverage_pct =<br/>committed / (committed + on-demand)"]
    OnD --> Cov
    Comm --> Util["utilization_pct =<br/>used / purchased"]
    Cov --> Find["FIN-CC-001 low coverage"]
    Util --> Find2["FIN-CC-002 under-utilized"]

    style Rows fill:#1f2937,color:#fff
    style Split fill:#b45309,color:#fff
    style Comm fill:#2563eb,color:#fff
    style OnD fill:#0891b2,color:#fff
    style Cov fill:#7c3aed,color:#fff
    style Util fill:#7c3aed,color:#fff
    style Find fill:#dc2626,color:#fff
    style Find2 fill:#dc2626,color:#fff
```

- **`FIN-CC-001`** fires when coverage is below target and there is meaningful
  on-demand-eligible spend — savings estimated as `eligible × assumed discount`.
- **`FIN-CC-002`** fires when a specific commitment is utilized below the 85%
  floor (severity escalates below 50%).
- Surfaced at **`GET /finops/coverage`** as a `CommitmentCoverageSummary`.

---

## 11. Spend Forecasting (Phase 4)

`finops/forecasting.py` projects month-end and next-month spend from the daily
FOCUS series using a **trailing daily average modulated by a day-of-week
seasonality factor** — deterministic and explainable, not a black box.

$$ \text{projected month-end} = \text{MTD} + \sum_{\text{remaining days}} \text{trailing avg} \times \text{seasonality}(\text{weekday}) $$

A forecast can be computed per `sub_account`, per `service`, or per `tag:<key>`,
which is exactly what budgets (section 13) reuse to project a breach. Surfaced at
**`GET /finops/forecast`** as a list of `SpendForecast` (trailing avg, MTD,
projected month-end, projected next-month).

---

## 12. Allocation — Showback / Chargeback & Tag Coverage (Phase 5)

`finops/allocation.py` groups spend by an allocation **dimension** (an allocation
tag such as `team`, `app`, `environment`, or `cost_center`, with case-insensitive
synonym matching) and measures how much spend can actually be attributed.

```mermaid
flowchart LR
    Rows["FOCUS rows"] --> Group["Group by tag value<br/>(team / app / env / cost_center)"]
    Group --> Tagged["Allocated groups"]
    Group --> Untag["Unallocated bucket<br/>(missing tag)"]
    Tagged --> Cov["coverage_pct =<br/>allocated / total"]
    Untag --> Cov
    Cov --> Find["FIN-AL-001<br/>low coverage + $ unallocated"]

    style Rows fill:#1f2937,color:#fff
    style Group fill:#2563eb,color:#fff
    style Tagged fill:#16a34a,color:#fff
    style Untag fill:#b45309,color:#fff
    style Cov fill:#7c3aed,color:#fff
    style Find fill:#dc2626,color:#fff
```

- **`allocate_spend(dimension)`** → `AllocationSummary` (groups, allocated vs
  unallocated, coverage %). Surfaced at **`GET /finops/allocation`**.
- **`compute_tag_coverage()`** → cost-weighted coverage per default dimension.
  Surfaced at **`GET /finops/coverage-tags`**.
- **`FIN-AL-001`** is a *governance* finding (no dollar claim, `method = NONE`)
  raised when coverage is below target **and** unallocated spend clears a floor —
  generalizing the old per-resource `MissingCostTags` rule into an account metric.

---

## 13. Budgets, Anomalies & Unit Economics — the "Operate" Layer (Phase 5)

The final phase reaches FinOps "Operate" maturity with three more pure-model
capabilities over the FOCUS ledger.

```mermaid
flowchart TD
    Ledger[("focus_costs")] --> B["Budgets<br/>finops/budgets.py"]
    Ledger --> A["Anomalies<br/>finops/anomaly.py"]
    Ledger --> U["Unit economics<br/>finops/unit_economics.py"]
    Budgets[("budgets<br/>partition: /tenant_id")] --> B

    B --> Bf["FIN-BG-001 breach<br/>FIN-BG-002 projected breach"]
    A --> Af["FIN-AN-001 spend spike"]
    U --> Uf["cost per tenant-defined unit"]

    style Ledger fill:#1e3a8a,color:#fff
    style Budgets fill:#1e3a8a,color:#fff
    style B fill:#2563eb,color:#fff
    style A fill:#0891b2,color:#fff
    style U fill:#7c3aed,color:#fff
    style Bf fill:#dc2626,color:#fff
    style Af fill:#dc2626,color:#fff
    style Uf fill:#16a34a,color:#fff
```

- **Budgets** — a `Budget` (scoped to whole subscription, a service, or a tag
  value) is evaluated for month-to-date actual **and** a projected month-end
  (reusing the section-11 forecast). Status is `OK` → `WARN` (over threshold) →
  `BREACH` (actual over) → `PROJECTED_BREACH` (forecast over), emitting
  `FIN-BG-001` / `FIN-BG-002`. CRUD at **`POST/GET/DELETE /finops/budgets`**;
  evaluation at **`GET /finops/budgets/status`**.
- **Anomalies** — a rolling mean/standard-deviation baseline (default 14-day
  window, min 7 periods) flags days whose spend exceeds a z-score threshold;
  severity scales with deviation (z≥3 MEDIUM, ≥4 HIGH, ≥5 CRITICAL), emitting
  `FIN-AN-001`. Surfaced at **`GET /finops/anomalies`**.
- **Unit economics** — divides MTD and projected spend by a tenant-defined
  denominator (active customers, transactions, …) to express cost efficiency.
  Surfaced at **`GET /finops/unit-economics`**.

---

## 14. Data Stores & API Surface

```mermaid
flowchart LR
    subgraph COSMOS["Cosmos DB (serverless)"]
        FC[("focus_costs<br/>/tenant_id")]
        BG[("budgets<br/>/tenant_id")]
    end
    subgraph API["/finops/* (tenant + subscription scoped)"]
        E1["GET /coverage"]
        E2["GET /forecast"]
        E3["GET /allocation"]
        E4["GET /coverage-tags"]
        E5["GET /anomalies"]
        E6["GET /unit-economics"]
        E7["GET/POST/DELETE /budgets"]
        E8["GET /budgets/status"]
    end
    FC --> API
    BG --> E7 & E8
    API --> UI["Frontend<br/>Cost Explorer · Optimization · Budgets"]

    style COSMOS fill:#1e3a8a,color:#fff
    style FC fill:#2563eb,color:#fff
    style BG fill:#2563eb,color:#fff
    style API fill:#0891b2,color:#fff
    style UI fill:#ea580c,color:#fff
```

- **Containers** are provisioned by Terraform (`infra/main.tf`), not auto-created
  by the app: `focus_costs` (phase 1) and `budgets` (phase 5), both partitioned
  by `/tenant_id`.
- **Every `/finops/*` endpoint is tenant- and subscription-scoped** and degrades
  gracefully: no subscription, missing repository, or a Cosmos error returns an
  empty / zeroed payload (or `[]`) instead of erroring.
- **Frontend:** the React app surfaces this via the **Cost Explorer**,
  **Optimization** (allocation, tag coverage, anomalies, unit economics), and
  **Budgets** pages, all backed by `frontend/src/api/finops.ts`.

---

## 15. The Guards (where cost degrades safely)

Every external billing/pricing touchpoint is wrapped. Failure is expected and
handled — it is never allowed to crash a scan or blank the dashboard.

```mermaid
flowchart TD
    G1["EMPTY-INPUT SHORT-CIRCUIT<br/>No resource ids to price to {} (no API call)"]
    G2["ACTUAL-COST FAILURE<br/>Throttle / denied / outage to {} + warning"]
    G3["LIST-PRICE MISS<br/>price &lt;= 0 or None to default / 0.0"]
    G4["STATIC CATALOG FALLBACK<br/>Offline-only, logged as a fallback"]
    G5["RIGHTSIZING FAILURE<br/>Missing price to savings not stamped"]
    G6["ID NORMALISATION<br/>Lower-case ids so clouds compare cleanly"]

    G1 --> G2 --> G3 --> G4 --> G5 --> G6

    style G1 fill:#b45309,color:#fff
    style G2 fill:#b45309,color:#fff
    style G3 fill:#b45309,color:#fff
    style G4 fill:#7c3aed,color:#fff
    style G5 fill:#0e7490,color:#fff
    style G6 fill:#16a34a,color:#fff
```

| Guard | Stage | Effect | Business rationale |
|-------|-------|--------|--------------------|
| **Empty-input short-circuit** | Entry | No ids → `{}`, zero API calls | Speed; no wasted billing quota |
| **Actual-cost graceful fail** | Billing API | Outage → `{}` + warning | Cost is enrichment, never a blocker |
| **List-price miss handling** | Pricing API | `<= 0` / `None` → default | A bad price never poisons the dashboard |
| **Static catalog fallback** | Pricing API | Logged offline last resort | Works air-gapped; never silently authoritative |
| **Rightsizing fail-safe** | Estimate | Missing price → no stamp | No misleading savings claims |
| **Id normalisation** | Exit | Lower-case ids | Correct cross-cloud joins |

---

## 16. One-Page Executive Summary

```mermaid
flowchart LR
    subgraph IN["INPUT"]
        A["Customer cloud bill<br/>(read-only access)"]
    end
    subgraph SEAM["COST PROVIDER SEAM"]
        B["One contract:<br/>actual cost + list price"]
    end
    subgraph CLOUDS["LIVE PRICING SOURCES"]
        C["Azure: Cost Mgmt + Retail"]
        D["AWS: Cost Explorer + Price List"]
        E["GCP: BigQuery + Catalog"]
    end
    subgraph LEDGER["FOCUS LEDGER + ANALYTICS"]
        L["focus_costs to coverage, forecast,<br/>allocation, budgets, anomalies, units"]
    end
    subgraph OUT["OUTPUT"]
        F["Per-resource cost + rightsizing<br/>+ waste $ + budgets/alerts<br/>+ showback/chargeback"]
    end

    A --> B --> C & D & E --> L --> F

    style IN fill:#1f2937,color:#fff
    style SEAM fill:#1e3a8a,color:#fff
    style CLOUDS fill:#0891b2,color:#fff
    style LEDGER fill:#7c3aed,color:#fff
    style OUT fill:#16a34a,color:#fff
```

**Bottom line for the business:**
- Every resource carries a **real dollar figure** sourced live from the cloud
  bill — no hardcoded prices.
- One clean **billing window** makes Azure, AWS, and GCP numbers directly
  comparable.
- **Actual-first, list-price-fallback** means even brand-new resources get a
  credible cost.
- **Rightsizing savings are real price deltas** — and where the cloud's own
  advisor agrees, the number is stamped **DIRECT** (highest confidence).
- **From cost to decisions** — one FOCUS ledger powers commitment coverage,
  spend forecasting, showback/chargeback allocation, budgets with breach alerts,
  anomaly detection, and unit economics, identically across Azure, AWS, and GCP.
- **Trustworthy by design** — every billing/pricing/analytics call is tenant- and
  subscription-scoped and degrades gracefully, so an outage never crashes a scan
  or blanks the dashboard.
