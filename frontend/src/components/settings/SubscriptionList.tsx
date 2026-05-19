import { useEffect, useMemo, useState } from "react";
import {
  ConnectTenantWizard,
  type WizardStep,
} from "./ConnectTenantWizard";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Alert, AlertDescription } from "../ui/alert";
import { useSubscriptions } from "../../hooks/useSubscriptions";
import { getBillingStatus, type BillingStatus } from "../../api/billing";
import { getOnboardingInfo, type OnboardingInfo } from "../../api/onboarding";
import { LoadingSpinner } from "../common/LoadingSpinner";
import type { Subscription } from "../../types";

const TIER_CAPS: Record<string, number> = {
  FREE: 1,
  PRO: 3,
  ENTERPRISE: -1,
};

const GUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

interface UpgradeRequiredDetail {
  error: string;
  current_tier?: string;
  cap?: number;
  current?: number;
}

interface ApiErrorShape {
  response?: { status?: number; data?: { detail?: unknown } };
  code?: string;
  message?: string;
}

function formatApiError(err: unknown, fallback: string): string {
  const e = err as ApiErrorShape;
  if (e?.response) {
    const status = e.response.status;
    const detail = e.response.data?.detail;
    if (typeof detail === "string") return `${status}: ${detail}`;
    if (detail && typeof detail === "object") {
      try {
        return `${status}: ${JSON.stringify(detail)}`;
      } catch {
        return `Request failed with status ${status}`;
      }
    }
    return `Request failed with status ${status}`;
  }
  if (e?.code === "ERR_NETWORK") {
    return (
      "Could not reach the CloudGuardIQ API. Check your connection or sign in again, then retry."
    );
  }
  if (e?.code === "ECONNABORTED") {
    return "Request timed out. Please retry.";
  }
  return e?.message ?? fallback;
}

export function SubscriptionList() {
  const { subscriptions, loading, add, remove, toggle, replace } =
    useSubscriptions();
  const [billingStatus, setBillingStatus] = useState<BillingStatus | null>(null);
  const [onboarding, setOnboarding] = useState<OnboardingInfo | null>(null);
  const [accessDenied, setAccessDenied] = useState<{
    message: string;
    az_command: string;
  } | null>(null);
  useEffect(() => {
    let cancelled = false;
    getBillingStatus()
      .then((s) => { if (!cancelled) setBillingStatus(s); })
      .catch(() => { if (!cancelled) setBillingStatus(null); });
    getOnboardingInfo()
      .then((info) => { if (!cancelled) setOnboarding(info); })
      .catch(() => { if (!cancelled) setOnboarding(null); });
    return () => { cancelled = true; };
  }, []);
  const tier = billingStatus?.tier ?? "FREE";
  const cap = TIER_CAPS[tier] ?? 1;

  const [newId, setNewId] = useState("");
  const [newName, setNewName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [upgradeMsg, setUpgradeMsg] = useState<string | null>(null);

  // Edit-in-place state: the subscription_id of the row currently being
  // edited, plus the working copy of its fields.
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editId, setEditId] = useState("");
  const [editName, setEditName] = useState("");
  const [editSubmitting, setEditSubmitting] = useState(false);

  // Cross-tenant onboarding wizard (Phase 3). The wizard component itself
  // persists progress through sessionStorage so we can resume after the
  // admin-consent redirect bounces the user back to /settings.
  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardInitial, setWizardInitial] = useState<{
    tenantId: string;
    step: WizardStep;
  }>({ tenantId: "", step: "tenant" });

  useEffect(() => {
    // If sessionStorage already has wizard state (because the consent
    // callback handler in Settings.tsx primed it), auto-open the wizard
    // at the persisted step.
    try {
      const raw = sessionStorage.getItem("cguardiq.connectWizard");
      if (!raw) return;
      const parsed = JSON.parse(raw) as {
        tenantId: string;
        step: WizardStep;
      };
      if (parsed?.tenantId && parsed?.step) {
        setWizardInitial(parsed);
        setWizardOpen(true);
      }
    } catch {
      /* ignore */
    }
  }, []);

  const counter = useMemo(() => {
    const total = subscriptions.length;
    if (cap < 0) return `${total} of unlimited used (${tier})`;
    return `${total} of ${cap} used (${tier})`;
  }, [subscriptions.length, cap, tier]);

  if (loading) return <LoadingSpinner />;

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setUpgradeMsg(null);
    setAccessDenied(null);
    if (!GUID_RE.test(newId)) {
      setError("Subscription ID must be a valid Azure GUID.");
      return;
    }
    setSubmitting(true);
    try {
      await add(newId, newName);
      setNewId("");
      setNewName("");
    } catch (err) {
      const e = err as ApiErrorShape & {
        response?: { status?: number; data?: { detail?: UpgradeRequiredDetail | string } };
      };
      if (e.response?.status === 402) {
        const detail = e.response.data?.detail;
        if (typeof detail === "object" && detail?.error === "upgrade_required") {
          setUpgradeMsg(
            `You're on the ${detail.current_tier ?? tier} plan (${detail.current}/${detail.cap}). ` +
              "Upgrade to add more subscriptions.",
          );
        } else {
          setUpgradeMsg("Upgrade required to add more subscriptions.");
        }
      } else if (e.response?.status === 400) {
        const detail = e.response.data?.detail as
          | { error?: string; message?: string; az_command?: string }
          | string
          | undefined;
        if (typeof detail === "object" && detail?.error === "access_denied") {
          setAccessDenied({
            message:
              detail.message ??
              "CloudGuardIQ does not have Reader access on this subscription.",
            az_command: detail.az_command ?? "",
          });
        } else {
          setError(formatApiError(err, "Failed to add subscription"));
        }
      } else {
        setError(formatApiError(err, "Failed to add subscription"));
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleRemove = async (id: string, displayName: string) => {
    setError(null);
    const confirmed = window.confirm(
      `Remove subscription "${displayName || id}"?\n\n` +
        "Stops scans immediately. Existing findings are kept for 30 days " +
        "so re-linking the same subscription restores your history. After " +
        "that they are permanently deleted.",
    );
    if (!confirmed) return;
    try {
      await remove(id);
    } catch (err) {
      setError(formatApiError(err, "Failed to remove subscription"));
    }
  };

  const handleToggle = async (id: string, currentState: string) => {
    setError(null);
    const next = currentState === "Enabled" ? "Disabled" : "Enabled";
    try {
      await toggle(id, next);
    } catch (err) {
      setError(formatApiError(err, "Failed to update subscription"));
    }
  };

  const startEdit = (sub: Subscription) => {
    setError(null);
    setUpgradeMsg(null);
    setEditingId(sub.subscription_id);
    setEditId(sub.subscription_id);
    setEditName(sub.display_name);
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditId("");
    setEditName("");
  };

  const saveEdit = async (originalId: string) => {
    setError(null);
    setUpgradeMsg(null);
    const trimmedId = editId.trim().toLowerCase();
    if (!GUID_RE.test(trimmedId)) {
      setError("Subscription ID must be a valid Azure GUID.");
      return;
    }
    if (
      trimmedId !== originalId &&
      subscriptions.some((s) => s.subscription_id === trimmedId)
    ) {
      setError("That subscription is already linked.");
      return;
    }
    setEditSubmitting(true);
    try {
      await replace(originalId, trimmedId, editName);
      cancelEdit();
    } catch (err) {
      setError(formatApiError(err, "Failed to update subscription"));
    } finally {
      setEditSubmitting(false);
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">Azure Subscriptions</CardTitle>
        <span className="text-xs text-[hsl(var(--muted-foreground))]">{counter}</span>
      </CardHeader>
      <CardContent className="space-y-4">
        {upgradeMsg && (
          <Alert>
            <AlertDescription>
              {upgradeMsg}{" "}
              <a
                href="/settings?tab=billing"
                className="font-semibold text-blue-600 underline"
              >
                Upgrade plan
              </a>
            </AlertDescription>
          </Alert>
        )}
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {accessDenied && (
          <Alert variant="destructive">
            <AlertDescription>
              <div className="font-medium">Access denied</div>
              <p className="mt-1 text-xs">{accessDenied.message}</p>
              {accessDenied.az_command && (
                <pre className="mt-2 overflow-x-auto rounded bg-black/80 p-2 text-xs text-emerald-300">{accessDenied.az_command}</pre>
              )}
            </AlertDescription>
          </Alert>
        )}

        {wizardOpen ? (
          <ConnectTenantWizard
            onClose={() => {
              setWizardOpen(false);
              setWizardInitial({ tenantId: "", step: "tenant" });
            }}
            initialTenantId={wizardInitial.tenantId}
            initialStep={wizardInitial.step}
          />
        ) : (
          <div className="flex items-center justify-between rounded border border-dashed p-3">
            <div>
              <div className="text-sm font-medium">
                Connect another tenant
              </div>
              <p className="text-xs text-[hsl(var(--muted-foreground))]">
                Walk a customer through admin consent + Reader role + sub discovery.
              </p>
            </div>
            <Button
              onClick={() => {
                setWizardInitial({ tenantId: "", step: "tenant" });
                setWizardOpen(true);
              }}
            >
              Start onboarding wizard
            </Button>
          </div>
        )}

        <form onSubmit={handleAdd} className="space-y-2 rounded border p-3">
          <div className="text-sm font-medium">Link a new Azure subscription</div>
          <p className="text-xs text-[hsl(var(--muted-foreground))]">
            Grant the CloudGuardIQ managed identity{" "}
            <span className="font-mono">Reader</span> on the subscription, then enter
            its ID below.
          </p>
          {onboarding && onboarding.azure_principal_id &&
            !onboarding.azure_principal_id.startsWith("<") && (
            <details className="text-xs">
              <summary className="cursor-pointer text-blue-600 underline">
                Show grant command
              </summary>
              <pre className="mt-1 overflow-x-auto rounded bg-black/80 p-2 text-emerald-300">{onboarding.az_command_template}</pre>
              <p className="mt-1 text-[hsl(var(--muted-foreground))]">
                Replace <span className="font-mono">&lt;your-subscription-id&gt;</span>{" "}
                with the GUID, run from a shell signed in as a subscription Owner.
              </p>
            </details>
          )}
          <div className="flex flex-col gap-2 md:flex-row">
            <input
              type="text"
              placeholder="00000000-0000-0000-0000-000000000000"
              value={newId}
              onChange={(e) => setNewId(e.target.value.trim())}
              className="flex-1 rounded border px-2 py-1 text-sm font-mono"
              required
            />
            <input
              type="text"
              placeholder="Display name (optional)"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              className="flex-1 rounded border px-2 py-1 text-sm"
            />
            <Button type="submit" disabled={submitting}>
              {submitting ? "Adding…" : "Add"}
            </Button>
          </div>
        </form>

        <div className="space-y-2">
          {subscriptions.map((sub) =>
            editingId === sub.subscription_id ? (
              <div
                key={sub.subscription_id}
                className="space-y-2 rounded border border-blue-300 bg-blue-50/40 p-3"
              >
                <div className="text-sm font-medium">Edit subscription</div>
                <p className="text-xs text-[hsl(var(--muted-foreground))]">
                  Fix a wrong subscription ID or rename the link. Changing the ID
                  re-creates the link with the new GUID.
                </p>
                <div className="flex flex-col gap-2 md:flex-row">
                  <input
                    type="text"
                    value={editId}
                    onChange={(e) => setEditId(e.target.value.trim())}
                    className="flex-1 rounded border px-2 py-1 text-sm font-mono"
                    placeholder="00000000-0000-0000-0000-000000000000"
                    required
                  />
                  <input
                    type="text"
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    className="flex-1 rounded border px-2 py-1 text-sm"
                    placeholder="Display name (optional)"
                  />
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      size="sm"
                      onClick={() => saveEdit(sub.subscription_id)}
                      disabled={editSubmitting}
                    >
                      {editSubmitting ? "Saving…" : "Save"}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={cancelEdit}
                      disabled={editSubmitting}
                    >
                      Cancel
                    </Button>
                  </div>
                </div>
              </div>
            ) : (
              <div
                key={sub.subscription_id}
                className="flex items-center justify-between rounded border p-3"
              >
                <div>
                  <div className="font-medium text-sm">{sub.display_name}</div>
                  <div className="text-xs font-mono text-[hsl(var(--muted-foreground))]">
                    {sub.subscription_id}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={
                      sub.state === "Enabled"
                        ? "text-xs text-emerald-600"
                        : "text-xs text-amber-600"
                    }
                  >
                    {sub.state}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => startEdit(sub)}
                  >
                    Edit
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleToggle(sub.subscription_id, sub.state)}
                  >
                    {sub.state === "Enabled" ? "Disable" : "Enable"}
                  </Button>
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => handleRemove(sub.subscription_id, sub.display_name)}
                  >
                    Remove
                  </Button>
                </div>
              </div>
            ),
          )}
          {subscriptions.length === 0 && (
            <p className="text-sm text-[hsl(var(--muted-foreground))]">
              No subscriptions linked yet. Add one above to start scanning.
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
