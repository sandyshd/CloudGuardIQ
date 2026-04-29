# CloudGuardIQ — SaaS Architecture Decisions (Phase 0)

> Locked decisions for the multi-tenant SaaS migration. These answers
> govern Phase 1+ implementation. Change requires an ADR-style update
> (date + reason) below.

Status: **Locked** — 2026-04-29
Owner: @sandyshd
Related plan: [saas-phased-plan.md](./saas-phased-plan.md)

---

## D1. Tenant identity source

**Decision:** Tenant ID is the Azure AD `tid` claim from the user's JWT.

- Already validated by `cloudguardiq/api/auth.py` against
  `CLOUDGUARDIQ_AZURE_TENANT_ID` (single-tenant mode today; relaxed in
  Phase 3).
- Stored as `tenant_id: str` on every domain row in Cosmos.
- A separate `customer_tenant_id` field is added in Phase 3 for the Azure
  AD tenant that **owns the subscription** (may differ from the user's
  CloudGuardIQ tenant).

Rejected alternatives:

- Internal UUID per organisation — adds a join, no clear benefit.
- Stripe `customer_id` — billing concern, not identity; leaks PII into
  logs.

---

## D2. Per-tier Azure subscription caps

**Decision:**

| Tier        | Max linked subscriptions | Encoding         |
| ----------- | ------------------------ | ---------------- |
| FREE        | 1                        | `1`              |
| PRO         | 10                       | `10`             |
| ENTERPRISE  | unlimited                | `-1` (sentinel)  |

- Config keys: `free_max_subscriptions=1`,
  `pro_max_subscriptions=10`, `enterprise_max_subscriptions=-1`.
- `-1` means "no cap"; middleware short-circuits the count check.
- Caps are inclusive ceilings (`count >= cap` → 402).

---

## D3. Downgrade policy (Pro → Free)

**Decision:** Auto-disable extras on tier change. No grace period in v1.

When Stripe webhook reports a downgrade and current count exceeds the new
cap:

1. Sort the tenant's subscriptions by `added_at` ASC (oldest first).
2. Keep the first `new_cap` subscriptions in `state="Enabled"`.
3. Set the remainder to `state="Disabled"` (do **not** delete — preserves
   findings history and lets users re-enable post-upgrade).
4. Disabled subs are skipped by the scheduler and rejected by `/scan*`
   with `403 subscription_disabled`.
5. Surface a banner in the UI: "Your plan supports N subscriptions. M
   subscription(s) were paused. Upgrade to re-enable."

Rejected alternatives:

- 7-day grace period — adds billing edge cases (re-upgrade during grace);
  defer to Phase 4.
- Delete extras — destroys customer data on a billing event.
- Block downgrade — Stripe is the source of truth; we cannot block it.

---

## D4. Cross-tenant authentication strategy (Phase 3)

**Decision:** Multi-tenant Entra ID app + **client certificate** stored in
Key Vault. Each customer-tenant scan uses
`ClientCertificateCredential(tenant_id=customer_tid, ...)`.

- Single app registration, marked `signInAudience=AzureADMultipleOrgs`.
- Cert (not secret) — longer rotation window, no plaintext credential in
  env vars, supported by Key Vault references.
- Cert auto-rotated annually via Key Vault; Terraform manages the
  certificate resource and the app's `key_credentials` attachment.
- Customer onboarding requires:
  1. Admin consent to the multi-tenant app in their Entra tenant.
  2. Granting `Reader` (and `Cost Management Reader`) to the app's
     service principal on each subscription they connect.

Rejected alternatives:

- **Azure Lighthouse** — clean delegation model but heavier onboarding
  (ARM template per delegation, harder UI flow). Revisit in Phase 5 as
  an *alternative* path, not the default.
- **Client secret** — shorter rotation, plaintext in pipeline, weaker
  posture for a security product.
- **Per-tenant app registration** — operationally infeasible; defeats the
  point of multi-tenant SaaS.

---

## D5. Cosmos partition strategy (Phase 1)

**Decision:** Keep existing partition keys (e.g. `/subscription_id`).
Add `tenant_id` as a **mandatory filter** in every query, not as a new PK.

- Repartitioning requires data migration and downtime — not justified
  for the current data volume.
- Every `WHERE` clause must start with `c.tenant_id = @tid AND ...`.
- Cross-tenant read prevention is enforced in code (repository helpers
  take `tenant_id` as a required argument), backed by a regression test
  that mocks two tenants.

Revisit when any single tenant exceeds ~10k findings or RU/s
throttling appears.

---

## D6. Scan ownership model

**Decision:** A scan belongs to exactly one `(tenant_id, subscription_id)`
pair. Scheduler emits one Service Bus message per pair. Workers are
stateless and idempotent on `scan_id`.

- No tenant-wide "scan everything" job — fan-out only.
- Per-subscription locking is deferred to Phase 4.

---

## D7. JWT claim handling

**Decision:** `tid` is required on every authenticated request. Missing
`tid` → 401. `oid` is captured for audit logs but is not part of any
authorization decision in v1.

- Audit log fields per request: `tenant_id`, `oid`, `subscription_id`
  (when applicable), `route`, `outcome`.

---

## Change log

| Date       | Change          | Reason |
| ---------- | --------------- | ------ |
| 2026-04-29 | Initial lock    | Phase 0 sign-off. |
