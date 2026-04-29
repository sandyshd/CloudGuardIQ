import { useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Alert, AlertDescription } from "../ui/alert";
import { useSubscriptions } from "../../hooks/useSubscriptions";
import { getBillingStatus, type BillingStatus } from "../../api/billing";
import { LoadingSpinner } from "../common/LoadingSpinner";

const TIER_CAPS: Record<string, number> = {
  FREE: 1,
  PRO: 10,
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

export function SubscriptionList() {
  const { subscriptions, loading, add, remove, toggle } = useSubscriptions();
  const [billingStatus, setBillingStatus] = useState<BillingStatus | null>(null);
  useEffect(() => {
    let cancelled = false;
    getBillingStatus()
      .then((s) => { if (!cancelled) setBillingStatus(s); })
      .catch(() => { if (!cancelled) setBillingStatus(null); });
    return () => { cancelled = true; };
  }, []);
  const tier = billingStatus?.tier ?? "FREE";
  const cap = TIER_CAPS[tier] ?? 1;

  const [newId, setNewId] = useState("");
  const [newName, setNewName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [upgradeMsg, setUpgradeMsg] = useState<string | null>(null);

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
      // axios error shape
      const e = err as {
        response?: { status?: number; data?: { detail?: UpgradeRequiredDetail | string } };
        message?: string;
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
      } else {
        setError(e.message ?? "Failed to add subscription");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleRemove = async (id: string) => {
    setError(null);
    try {
      await remove(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove subscription");
    }
  };

  const handleToggle = async (id: string, currentState: string) => {
    setError(null);
    const next = currentState === "Enabled" ? "Disabled" : "Enabled";
    try {
      await toggle(id, next);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update subscription");
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

        <form onSubmit={handleAdd} className="space-y-2 rounded border p-3">
          <div className="text-sm font-medium">Link a new Azure subscription</div>
          <p className="text-xs text-[hsl(var(--muted-foreground))]">
            Grant the CloudGuardIQ multi-tenant app{" "}
            <span className="font-mono">Reader</span> on the subscription, then enter
            its ID below.
          </p>
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
          {subscriptions.map((sub) => (
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
                  onClick={() => handleToggle(sub.subscription_id, sub.state)}
                >
                  {sub.state === "Enabled" ? "Disable" : "Enable"}
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => handleRemove(sub.subscription_id)}
                >
                  Remove
                </Button>
              </div>
            </div>
          ))}
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
