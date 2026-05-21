import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Bell } from "lucide-react";
import { useFindings } from "../../hooks/useFindings";
import { useSubscriptionContext } from "../../auth/SubscriptionContext";
import { Button } from "../ui/button";
import { cn, isOpenFinding } from "../../lib/utils";

const STORAGE_KEY = "cguardiq.notifSeen";

function loadSeen(): string[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as string[]) : [];
  } catch {
    return [];
  }
}

function persistSeen(ids: string[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(ids.slice(-200)));
  } catch {
    /* ignore */
  }
}

export function NotificationsMenu() {
  const navigate = useNavigate();
  const { selected } = useSubscriptionContext();
  const { findings } = useFindings(selected?.subscription_id);
  const [open, setOpen] = useState(false);
  const [seen, setSeen] = useState<string[]>(() => loadSeen());
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

  const critical = findings
    .filter((f) => f.severity === "CRITICAL" && isOpenFinding(f))
    .slice()
    .sort((a, b) => (b.detected_at || "").localeCompare(a.detected_at || ""));
  const top = critical.slice(0, 6);
  const seenSet = new Set(seen);
  const unread = top.filter((f) => !seenSet.has(f.finding_id)).length;

  const markAllRead = () => {
    const ids = Array.from(new Set([...seen, ...top.map((f) => f.finding_id)]));
    setSeen(ids);
    persistSeen(ids);
  };

  const goTo = (id: string) => {
    setOpen(false);
    markAllRead();
    navigate(`/findings/${id}`);
  };

  return (
    <div ref={ref} className="relative">
      <Button
        variant="ghost"
        size="icon"
        aria-label="Notifications"
        onClick={() => setOpen((v) => !v)}
        className="relative h-9 w-9"
      >
        <Bell className="h-4 w-4" />
        {unread > 0 && (
          <span className="absolute right-1.5 top-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-[hsl(var(--severity-critical))] px-1 text-[9px] font-bold leading-none text-white">
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </Button>
      {open && (
        <div className="absolute right-0 top-[calc(100%+6px)] z-40 w-80 overflow-hidden rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] shadow-xl">
          <div className="flex items-center justify-between border-b border-[hsl(var(--border))] px-3 py-2.5">
            <div className="text-sm font-semibold text-[hsl(var(--foreground))]">
              Notifications
            </div>
            {unread > 0 && (
              <button
                type="button"
                onClick={markAllRead}
                className="text-[11px] font-medium text-[hsl(var(--primary))] hover:underline"
              >
                Mark all read
              </button>
            )}
          </div>
          <ul className="max-h-80 overflow-y-auto py-1">
            {top.length === 0 ? (
              <li className="px-3 py-6 text-center text-xs text-[hsl(var(--muted-foreground))]">
                You're all caught up.
              </li>
            ) : (
              top.map((f) => {
                const isUnread = !seenSet.has(f.finding_id);
                return (
                  <li key={f.finding_id}>
                    <button
                      type="button"
                      onClick={() => goTo(f.finding_id)}
                      className="flex w-full items-start gap-2 px-3 py-2.5 text-left transition-colors hover:bg-[hsl(var(--accent)/0.15)]"
                    >
                      <span
                        className={cn(
                          "mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full",
                          isUnread ? "bg-[hsl(var(--severity-critical))]" : "bg-transparent",
                        )}
                      />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm font-medium text-[hsl(var(--foreground))]">
                          {f.rule_name}
                        </span>
                        <span className="block truncate text-[11px] text-[hsl(var(--muted-foreground))]">
                          {f.resource_snapshot?.resource_name || f.finding_type}
                        </span>
                      </span>
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
                navigate("/findings");
              }}
              className="flex w-full items-center justify-center rounded-md px-3 py-2 text-xs font-medium text-[hsl(var(--primary))] transition-colors hover:bg-[hsl(var(--primary)/0.08)]"
            >
              View all findings
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

