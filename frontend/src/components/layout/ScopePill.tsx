import { useNavigate } from "react-router-dom";
import { Layers } from "lucide-react";
import { useSubscriptionContext } from "../../auth/SubscriptionContext";

export function ScopePill() {
  const { subscriptions, selected, loading } = useSubscriptionContext();
  const navigate = useNavigate();

  if (loading) {
    return <div className="hidden h-9 w-44 animate-pulse rounded-md bg-[hsl(var(--muted))] md:block" />;
  }

  const enabled = subscriptions.filter((s) => s.state === "Enabled").length;
  if (enabled === 0) return null;

  const inScope = selected ? 1 : 0;
  const label = `${inScope} of ${enabled} ${enabled === 1 ? "subscription" : "subscriptions"}`;

  return (
    <button
      type="button"
      onClick={() => navigate("/settings")}
      title="Manage subscription scope"
      className="hidden h-9 items-center gap-2 rounded-full border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 text-xs font-medium text-[hsl(var(--foreground))] transition-colors hover:border-[hsl(var(--primary)/0.4)] hover:bg-[hsl(var(--primary)/0.05)] md:inline-flex"
    >
      <Layers className="h-3.5 w-3.5 text-[hsl(var(--primary))]" />
      <span>{label}</span>
    </button>
  );
}
