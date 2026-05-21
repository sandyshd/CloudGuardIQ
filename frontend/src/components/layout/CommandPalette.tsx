import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Bot,
  Command as CommandIcon,
  FileCheck,
  FileText,
  HeartPulse,
  History,
  LayoutDashboard,
  Plug,
  Search,
  Server,
  Settings as SettingsIcon,
  ShieldAlert,
  Sparkles,
  TrendingUp,
  Wallet,
  ClipboardCheck,
  CornerDownLeft,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useSubscriptionContext } from "../../auth/SubscriptionContext";
import { useFindings } from "../../hooks/useFindings";
import { cn } from "../../lib/utils";

const RECENT_KEY = "cguardiq.cmdRecent";
const RECENT_MAX = 6;

interface PaletteItem {
  id: string;
  label: string;
  hint?: string;
  icon: LucideIcon;
  group: string;
  keywords?: string;
  onSelect: () => void;
}

interface Props {
  open: boolean;
  onClose: () => void;
}

function loadRecent(): string[] {
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    return raw ? (JSON.parse(raw) as string[]) : [];
  } catch {
    return [];
  }
}

function persistRecent(ids: string[]) {
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(ids.slice(0, RECENT_MAX)));
  } catch {
    /* ignore */
  }
}

export function CommandPalette({ open, onClose }: Props) {
  const navigate = useNavigate();
  const { subscriptions, selected, setSelectedId } = useSubscriptionContext();
  const { findings } = useFindings(selected?.subscription_id);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [recent, setRecent] = useState<string[]>(() => loadRecent());
  const inputRef = useRef<HTMLInputElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    setQuery("");
    setActive(0);
    document.body.style.overflow = "hidden";
    const t = window.setTimeout(() => inputRef.current?.focus(), 10);
    return () => {
      document.body.style.overflow = "";
      window.clearTimeout(t);
    };
  }, [open]);

  const select = (item: PaletteItem) => {
    const next = [item.id, ...recent.filter((r) => r !== item.id)].slice(0, RECENT_MAX);
    setRecent(next);
    persistRecent(next);
    item.onSelect();
    onClose();
  };

  const items = useMemo<PaletteItem[]>(() => {
    const navItems: PaletteItem[] = [
      { id: "nav:overview", label: "Overview", icon: LayoutDashboard, group: "Navigation", keywords: "dashboard home", onSelect: () => navigate("/") },
      { id: "nav:findings", label: "Findings", icon: ShieldAlert, group: "Navigation", keywords: "issues alerts security", onSelect: () => navigate("/findings") },
      { id: "nav:resources", label: "Resources", icon: Server, group: "Navigation", keywords: "inventory assets", onSelect: () => navigate("/resources") },
      { id: "nav:policies", label: "Policies", icon: FileCheck, group: "Navigation", keywords: "rules", onSelect: () => navigate("/policies") },
      { id: "nav:cost", label: "Cost Explorer", icon: TrendingUp, group: "Navigation", keywords: "finops spend", onSelect: () => navigate("/finops") },
      { id: "nav:opt", label: "Optimization", icon: Sparkles, group: "Navigation", keywords: "savings rightsizing", onSelect: () => navigate("/finops/optimization") },
      { id: "nav:budgets", label: "Budgets", icon: Wallet, group: "Navigation", keywords: "spend alerts", onSelect: () => navigate("/finops/budgets") },
      { id: "nav:integrations", label: "Integrations", icon: Plug, group: "Navigation", keywords: "connect onboard", onSelect: () => navigate("/integrations") },
      { id: "nav:ai", label: "AI Remediation", icon: Bot, group: "Navigation", keywords: "fix gpt copilot", onSelect: () => navigate("/ai-fix") },
      { id: "nav:reports", label: "Reports", icon: FileText, group: "Navigation", keywords: "export pdf", onSelect: () => navigate("/reports") },
      { id: "nav:audit", label: "Audit Log", icon: History, group: "Navigation", keywords: "trail", onSelect: () => navigate("/audit") },
      { id: "nav:compliance", label: "Compliance", icon: ClipboardCheck, group: "Navigation", keywords: "framework cis pci", onSelect: () => navigate("/compliance") },
      { id: "nav:selfheal", label: "Self-Healing", icon: HeartPulse, group: "Navigation", keywords: "auto remediation", onSelect: () => navigate("/self-heal") },
      { id: "nav:settings", label: "Settings", icon: SettingsIcon, group: "Navigation", keywords: "config", onSelect: () => navigate("/settings") },
    ];

    const actionItems: PaletteItem[] = [
      { id: "act:scan", label: "Run posture scan", hint: "Trigger a fresh scan on the active subscription", icon: ShieldAlert, group: "Quick actions", keywords: "scan trigger", onSelect: () => navigate("/findings") },
      { id: "act:ai", label: "Ask AI assistant", hint: "Open AI Remediation", icon: Bot, group: "Quick actions", keywords: "chat copilot ask", onSelect: () => navigate("/ai-fix") },
      { id: "act:link", label: "Link a subscription", hint: "Open Settings to onboard", icon: Plug, group: "Quick actions", keywords: "onboard add", onSelect: () => navigate("/settings") },
      { id: "act:export", label: "Export findings as CSV", icon: FileText, group: "Quick actions", keywords: "download export", onSelect: () => navigate("/findings") },
    ];

    const subItems: PaletteItem[] = subscriptions
      .filter((s) => s.state === "Enabled")
      .slice(0, 8)
      .map((s) => ({
        id: `sub:${s.subscription_id}`,
        label: `Switch to ${s.display_name || s.subscription_id}`,
        hint: s.subscription_id,
        icon: Server,
        group: "Subscriptions",
        keywords: `${s.subscription_id} switch tenant scope`,
        onSelect: () => setSelectedId(s.subscription_id),
      }));

    const findingItems: PaletteItem[] = findings.slice(0, 12).map((f) => ({
      id: `find:${f.finding_id}`,
      label: f.rule_name,
      hint: `${f.severity} · ${f.resource_snapshot?.resource_name || f.finding_type}`,
      icon: ShieldAlert,
      group: "Findings",
      keywords: `${f.severity} ${f.finding_type} ${f.rule_id} ${f.resource_snapshot?.resource_name ?? ""}`,
      onSelect: () => navigate(`/findings/${f.finding_id}`),
    }));

    return [...actionItems, ...navItems, ...subItems, ...findingItems];
  }, [navigate, subscriptions, setSelectedId, findings]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) {
      const recentResolved = recent
        .map((id) => items.find((i) => i.id === id))
        .filter((x): x is PaletteItem => Boolean(x));
      const fallback = items.filter((i) => i.group === "Navigation").slice(0, 6);
      const seen = new Set(recentResolved.map((i) => i.id));
      const tail = fallback.filter((i) => !seen.has(i.id));
      const result = [
        ...recentResolved.map((i) => ({ ...i, group: "Recent" })),
        ...tail,
      ];
      return result;
    }
    return items.filter((i) => {
      const hay = `${i.label} ${i.hint ?? ""} ${i.keywords ?? ""} ${i.group}`.toLowerCase();
      return q.split(/\s+/).every((part) => hay.includes(part));
    });
  }, [items, query, recent]);

  useEffect(() => {
    setActive(0);
  }, [query]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setActive((a) => Math.min(a + 1, filtered.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActive((a) => Math.max(a - 1, 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        const item = filtered[active];
        if (item) select(item);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, filtered, active, onClose]);

  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-idx="${active}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [active]);

  if (!open) return null;

  // Group items in render order while preserving global active index.
  const groups: { name: string; items: { item: PaletteItem; idx: number }[] }[] = [];
  filtered.forEach((item, idx) => {
    const last = groups[groups.length - 1];
    if (last && last.name === item.group) {
      last.items.push({ item, idx });
    } else {
      groups.push({ name: item.group, items: [{ item, idx }] });
    }
  });

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      className="fixed inset-0 z-[80] flex items-start justify-center px-4 pt-[10vh]"
    >
      <button
        type="button"
        aria-label="Close command palette"
        onClick={onClose}
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
      />
      <div className="relative z-10 flex max-h-[70vh] w-full max-w-2xl flex-col overflow-hidden rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--popover))] shadow-2xl">
        <div className="flex items-center gap-2 border-b border-[hsl(var(--border))] px-3">
          <Search className="h-4 w-4 shrink-0 text-[hsl(var(--muted-foreground))]" />
          <input
            ref={inputRef}
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search resources, findings, actions…"
            className="h-12 flex-1 bg-transparent text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none"
          />
          <kbd className="hidden rounded border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-1.5 py-0.5 text-[10px] font-medium text-[hsl(var(--muted-foreground))] sm:inline-flex">
            ESC
          </kbd>
        </div>

        <div ref={listRef} className="flex-1 overflow-y-auto py-2">
          {filtered.length === 0 ? (
            <div className="px-4 py-10 text-center text-sm text-[hsl(var(--muted-foreground))]">
              No results for &ldquo;{query}&rdquo;.
            </div>
          ) : (
            groups.map((g) => (
              <div key={g.name} className="mb-1.5 last:mb-0">
                <div className="px-3 pb-1 pt-1.5 text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                  {g.name}
                </div>
                <ul>
                  {g.items.map(({ item, idx }) => (
                    <li key={item.id}>
                      <button
                        type="button"
                        data-idx={idx}
                        onMouseEnter={() => setActive(idx)}
                        onClick={() => select(item)}
                        className={cn(
                          "flex w-full items-center gap-3 px-3 py-2 text-left text-sm transition-colors",
                          idx === active
                            ? "bg-[hsl(var(--primary)/0.1)] text-[hsl(var(--foreground))]"
                            : "text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent)/0.1)]",
                        )}
                      >
                        <item.icon
                          className={cn(
                            "h-4 w-4 shrink-0",
                            idx === active
                              ? "text-[hsl(var(--primary))]"
                              : "text-[hsl(var(--muted-foreground))]",
                          )}
                        />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate font-medium">{item.label}</span>
                          {item.hint && (
                            <span className="block truncate text-[11px] text-[hsl(var(--muted-foreground))]">
                              {item.hint}
                            </span>
                          )}
                        </span>
                        {idx === active && (
                          <CornerDownLeft className="h-3.5 w-3.5 shrink-0 text-[hsl(var(--muted-foreground))]" />
                        )}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ))
          )}
        </div>

        <div className="flex items-center justify-between border-t border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.4)] px-3 py-2 text-[11px] text-[hsl(var(--muted-foreground))]">
          <span className="inline-flex items-center gap-1.5">
            <CommandIcon className="h-3 w-3" />
            CloudGuardIQ
          </span>
          <span className="hidden items-center gap-3 sm:inline-flex">
            <span><kbd className="rounded border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-1 font-medium">↑↓</kbd> navigate</span>
            <span><kbd className="rounded border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-1 font-medium">↵</kbd> select</span>
            <span><kbd className="rounded border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-1 font-medium">esc</kbd> close</span>
          </span>
        </div>
      </div>
    </div>
  );
}
