import { useNavigate } from "react-router-dom";
import { ChevronDown, Cloud, Link2 } from "lucide-react";
import { useSubscriptionContext } from "../../auth/SubscriptionContext";

function shortId(id: string): string {
  return id.length > 8 ? `${id.slice(0, 4)}…${id.slice(-4)}` : id;
}

export function SubscriptionSwitcher() {
  const navigate = useNavigate();
  const { subscriptions, selected, setSelectedId, loading } =
    useSubscriptionContext();

  const enabled = subscriptions.filter((s) => s.state === "Enabled");

  if (loading) {
    return (
      <div className="h-9 w-48 animate-pulse rounded bg-[hsl(var(--muted))]" />
    );
  }

  if (enabled.length === 0) {
    return (
      <button
        type="button"
        onClick={() => navigate("/settings")}
        className="inline-flex items-center gap-2 rounded border px-3 py-1.5 text-sm text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--muted))]"
      >
        <Link2 className="h-4 w-4" />
        Link a subscription
      </button>
    );
  }

  return (
    <label className="relative inline-flex items-center gap-2 rounded border px-3 py-1.5 text-sm hover:bg-[hsl(var(--muted))]">
      <Cloud className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
      <span className="sr-only">Active subscription</span>
      <select
        className="appearance-none bg-transparent pr-5 outline-none"
        value={selected?.subscription_id ?? ""}
        onChange={(e) => setSelectedId(e.target.value)}
      >
        {enabled.map((sub) => (
          <option key={sub.subscription_id} value={sub.subscription_id}>
            {sub.display_name || shortId(sub.subscription_id)}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2 h-4 w-4 text-[hsl(var(--muted-foreground))]" />
    </label>
  );
}
