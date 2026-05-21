import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Check, ChevronsUpDown, Cloud, Plus } from "lucide-react";
import { useSubscriptionContext } from "../../auth/SubscriptionContext";
import { cn } from "../../lib/utils";

interface Props {
  collapsed?: boolean;
}

function shortId(id: string): string {
  return id.length > 8 ? `${id.slice(0, 4)}…${id.slice(-4)}` : id;
}

export function TenantSwitcher({ collapsed }: Props) {
  const navigate = useNavigate();
  const { subscriptions, selected, setSelectedId, loading } = useSubscriptionContext();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const enabled = subscriptions.filter((s) => s.state === "Enabled");
  const filtered = query
    ? enabled.filter(
        (s) =>
          s.display_name.toLowerCase().includes(query.toLowerCase()) ||
          s.subscription_id.toLowerCase().includes(query.toLowerCase()),
      )
    : enabled;

  if (loading) {
    return (
      <div
        className={cn(
          "h-9 animate-pulse rounded-md bg-[hsl(var(--sidebar-accent)/0.6)]",
          collapsed ? "w-9" : "w-full",
        )}
      />
    );
  }

  if (collapsed) {
    return (
      <button
        type="button"
        onClick={() => navigate("/settings")}
        title={selected?.display_name || "Subscriptions"}
        className="flex h-9 w-9 items-center justify-center rounded-md border border-[hsl(var(--sidebar-border))] bg-[hsl(var(--sidebar-background))] text-[hsl(var(--sidebar-accent-foreground))] transition-colors hover:bg-[hsl(var(--sidebar-accent))]"
      >
        <Cloud className="h-4 w-4" />
      </button>
    );
  }

  if (enabled.length === 0) {
    return (
      <button
        type="button"
        onClick={() => navigate("/settings")}
        className="flex w-full items-center gap-2 rounded-md border border-dashed border-[hsl(var(--sidebar-border))] bg-[hsl(var(--sidebar-background))] px-3 py-2 text-left text-xs text-[hsl(var(--sidebar-muted))] transition-colors hover:border-[hsl(var(--primary)/0.6)] hover:text-[hsl(var(--sidebar-accent-foreground))]"
      >
        <Plus className="h-3.5 w-3.5" />
        Link a subscription
      </button>
    );
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 rounded-md border border-[hsl(var(--sidebar-border))] bg-[hsl(var(--sidebar-background))] px-2.5 py-2 text-left transition-colors hover:bg-[hsl(var(--sidebar-accent))]"
      >
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-[hsl(var(--primary)/0.15)] text-[hsl(var(--primary))]">
          <Cloud className="h-3.5 w-3.5" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium text-[hsl(var(--sidebar-accent-foreground))]">
            {selected?.display_name || shortId(selected?.subscription_id ?? "")}
          </span>
          <span className="block truncate font-mono text-[10px] text-[hsl(var(--sidebar-muted))]">
            {selected ? shortId(selected.subscription_id) : `${enabled.length} linked`}
          </span>
        </span>
        <ChevronsUpDown className="h-3.5 w-3.5 shrink-0 text-[hsl(var(--sidebar-muted))]" />
      </button>

      {open && (
        <div className="absolute left-0 right-0 top-[calc(100%+6px)] z-40 overflow-hidden rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] shadow-lg">
          <div className="border-b border-[hsl(var(--border))] p-2">
            <input
              type="search"
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search subscriptions…"
              className="h-8 w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--card))] px-2.5 text-xs text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
            />
          </div>
          <ul className="max-h-72 overflow-y-auto py-1">
            {filtered.length === 0 ? (
              <li className="px-3 py-4 text-center text-xs text-[hsl(var(--muted-foreground))]">
                No matches
              </li>
            ) : (
              filtered.map((sub) => {
                const active = selected?.subscription_id === sub.subscription_id;
                return (
                  <li key={sub.subscription_id}>
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedId(sub.subscription_id);
                        setOpen(false);
                        setQuery("");
                      }}
                      className={cn(
                        "flex w-full items-center gap-2 px-3 py-2 text-left text-sm transition-colors",
                        active
                          ? "bg-[hsl(var(--primary)/0.08)] text-[hsl(var(--primary))]"
                          : "text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent)/0.15)]",
                      )}
                    >
                      <Cloud className="h-3.5 w-3.5 shrink-0 text-[hsl(var(--muted-foreground))]" />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate font-medium">
                          {sub.display_name || shortId(sub.subscription_id)}
                        </span>
                        <span className="block truncate font-mono text-[10px] text-[hsl(var(--muted-foreground))]">
                          {sub.subscription_id}
                        </span>
                      </span>
                      {active && <Check className="h-3.5 w-3.5 shrink-0" />}
                    </button>
                  </li>
                );
              })
            )}
          </ul>
          <div className="border-t border-[hsl(var(--border))] p-1">
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                navigate("/settings");
              }}
              className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-xs text-[hsl(var(--muted-foreground))] transition-colors hover:bg-[hsl(var(--accent)/0.15)] hover:text-[hsl(var(--foreground))]"
            >
              <Plus className="h-3.5 w-3.5" />
              Link a new subscription
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
