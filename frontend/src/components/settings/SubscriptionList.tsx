import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Cloud, Pencil, Power, Trash2 } from "lucide-react";
import { useSubscriptions } from "../../hooks/useSubscriptions";
import { LoadingSpinner } from "../common/LoadingSpinner";
import type { Subscription } from "../../types";

const GUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

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
    return "Could not reach the CloudGuardIQ API. Check your connection or sign in again, then retry.";
  }
  if (e?.code === "ECONNABORTED") {
    return "Request timed out. Please retry.";
  }
  return e?.message ?? fallback;
}

const inputClass =
  "h-9 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))] focus-visible:border-[hsl(var(--ring))]";

export function SubscriptionList() {
  const { subscriptions, loading, remove, toggle, replace } = useSubscriptions();

  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editId, setEditId] = useState("");
  const [editName, setEditName] = useState("");
  const [editSubmitting, setEditSubmitting] = useState(false);

  const counter = useMemo(() => {
    const total = subscriptions.length;
    return `${total} linked`;
  }, [subscriptions.length]);

  if (loading) return <LoadingSpinner />;

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
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Linked subscriptions</CardTitle>
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
            {counter}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {subscriptions.length === 0 ? (
          <div className="flex items-start gap-3 rounded-md border border-dashed border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.4)] p-4 text-sm text-[hsl(var(--muted-foreground))]">
            <Cloud className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--primary))]" />
            <p>
              No subscriptions linked yet. Use{" "}
              <span className="font-medium text-[hsl(var(--foreground))]">
                Multi-Cloud Onboarding
              </span>{" "}
              above to connect an Azure tenant, AWS account, or GCP project.
            </p>
          </div>
        ) : (
          <p className="text-xs text-[hsl(var(--muted-foreground))]">
            To add a new subscription, account, or project use{" "}
            <span className="font-medium text-[hsl(var(--foreground))]">
              Multi-Cloud Onboarding
            </span>{" "}
            above.
          </p>
        )}

        <div className="space-y-2">
          {subscriptions.map((sub) =>
            editingId === sub.subscription_id ? (
              <div
                key={sub.subscription_id}
                className="space-y-3 rounded-[var(--radius)] border border-[hsl(var(--primary)/0.4)] bg-[hsl(var(--primary)/0.05)] p-4"
              >
                <div>
                  <div className="text-sm font-semibold text-[hsl(var(--foreground))]">
                    Edit subscription
                  </div>
                  <p className="mt-0.5 text-xs text-[hsl(var(--muted-foreground))]">
                    Fix a wrong subscription ID or rename the link. Changing the
                    ID re-creates the link with the new GUID.
                  </p>
                </div>
                <div className="flex flex-col gap-2 md:flex-row">
                  <input
                    type="text"
                    value={editId}
                    onChange={(e) => setEditId(e.target.value.trim())}
                    className={`${inputClass} flex-1 font-mono`}
                    placeholder="00000000-0000-0000-0000-000000000000"
                    required
                  />
                  <input
                    type="text"
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    className={`${inputClass} flex-1`}
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
                className="flex flex-wrap items-center justify-between gap-3 rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-3 transition-colors hover:border-[hsl(var(--primary)/0.4)]"
              >
                <div className="flex min-w-0 items-center gap-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-[hsl(var(--primary)/0.12)] text-[hsl(var(--primary))]">
                    <Cloud className="h-4 w-4" />
                  </div>
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium text-[hsl(var(--foreground))]">
                      {sub.display_name || "Unnamed subscription"}
                    </div>
                    <div className="truncate font-mono text-[11px] text-[hsl(var(--muted-foreground))]">
                      {sub.subscription_id}
                    </div>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge
                    variant={sub.state === "Enabled" ? "success" : "secondary"}
                  >
                    {sub.state}
                  </Badge>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => startEdit(sub)}
                  >
                    <Pencil className="h-3.5 w-3.5" />
                    Edit
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleToggle(sub.subscription_id, sub.state)}
                  >
                    <Power className="h-3.5 w-3.5" />
                    {sub.state === "Enabled" ? "Disable" : "Enable"}
                  </Button>
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() =>
                      handleRemove(sub.subscription_id, sub.display_name)
                    }
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Remove
                  </Button>
                </div>
              </div>
            ),
          )}
        </div>
      </CardContent>
    </Card>
  );
}
