import { useEffect, useMemo, useState } from "react";
import { NavLink } from "react-router-dom";
import type { LucideIcon } from "lucide-react";
import {
  Bot,
  BookOpen,
  ClipboardCheck,
  FileCheck,
  FileText,
  HeartPulse,
  History,
  LayoutDashboard,
  PanelLeftClose,
  PanelLeftOpen,
  Plug,
  Server,
  Settings as SettingsIcon,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TrendingUp,
  Wallet,
} from "lucide-react";
import { cn } from "../../lib/utils";
import { useFindings } from "../../hooks/useFindings";
import { useSubscriptionContext } from "../../auth/SubscriptionContext";
import { TenantSwitcher } from "./TenantSwitcher";
import { SidebarUser } from "./SidebarUser";

type BadgeKind = "critical" | "savings" | null;

interface NavItem {
  to: string;
  icon: LucideIcon;
  label: string;
  end?: boolean;
  badge?: BadgeKind;
}

interface NavSection {
  label: string;
  items: NavItem[];
}

const SECTIONS: NavSection[] = [
  {
    label: "Posture",
    items: [
      { to: "/", icon: LayoutDashboard, label: "Overview", end: true },
      { to: "/findings", icon: ShieldAlert, label: "Findings", badge: "critical" },
      { to: "/resources", icon: Server, label: "Resources" },
      { to: "/policies", icon: FileCheck, label: "Policies" },
      { to: "/compliance", icon: ClipboardCheck, label: "Compliance" },
    ],
  },
  {
    label: "FinOps",
    items: [
      { to: "/finops", icon: TrendingUp, label: "Cost Explorer" },
      { to: "/finops/optimization", icon: Sparkles, label: "Optimization", badge: "savings" },
      { to: "/finops/budgets", icon: Wallet, label: "Budgets" },
    ],
  },
  {
    label: "Platform",
    items: [
      { to: "/integrations", icon: Plug, label: "Integrations" },
      { to: "/ai-fix", icon: Bot, label: "AI Remediation" },
      { to: "/self-heal", icon: HeartPulse, label: "Self-Healing" },
      { to: "/reports", icon: FileText, label: "Reports" },
      { to: "/audit", icon: History, label: "Audit Log" },
    ],
  },
];

const STORAGE_KEY = "cguardiq.sidebarCollapsed";

function formatSavings(usd: number): string {
  if (usd >= 1000) return `$${(usd / 1000).toFixed(usd >= 10000 ? 0 : 1)}k`;
  return `$${Math.round(usd)}`;
}

export function Sidebar() {
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) === "1";
    } catch {
      return false;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, collapsed ? "1" : "0");
    } catch {
      /* ignore */
    }
  }, [collapsed]);

  const { selected } = useSubscriptionContext();
  const { findings } = useFindings(selected?.subscription_id);

  const counts = useMemo(() => {
    const open = findings.filter((f) => (f.status ?? "OPEN") === "OPEN");
    const critical = open.filter((f) => f.severity === "CRITICAL").length;
    const savings = open
      .filter((f) => f.finding_type === "FINOPS")
      .reduce((acc, f) => acc + (f.waste_monthly_usd || 0), 0);
    return { critical, savings };
  }, [findings]);

  const width = collapsed ? "w-[64px]" : "w-[248px]";

  return (
    <aside
      className={cn(
        "relative z-20 hidden h-screen flex-col border-r md:flex border-[hsl(var(--sidebar-border))] bg-[hsl(var(--sidebar-background))] text-[hsl(var(--sidebar-foreground))] transition-[width] duration-200 ease-out",
        width,
      )}
    >
      {/* Brand + Switcher */}
      <div className="flex flex-col gap-3 border-b border-[hsl(var(--sidebar-border))] p-3">
        <div className={cn("flex items-center gap-2", collapsed && "justify-center")}>
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-[hsl(var(--primary))] to-[hsl(var(--accent))] shadow-sm">
            <ShieldCheck className="h-4 w-4 text-white" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <div className="truncate text-[15px] font-semibold leading-tight text-[hsl(var(--sidebar-accent-foreground))]">
                CloudGuardIQ
              </div>
              <div className="truncate text-[10px] uppercase tracking-wider text-[hsl(var(--sidebar-muted))]">
                CSPM &middot; FinOps
              </div>
            </div>
          )}
        </div>
        <TenantSwitcher collapsed={collapsed} />
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-2 py-3">
        {SECTIONS.map((section) => (
          <div key={section.label} className="mb-4 last:mb-0">
            {!collapsed ? (
              <div className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--sidebar-muted))]">
                {section.label}
              </div>
            ) : (
              <div className="mx-3 mb-1 h-px bg-[hsl(var(--sidebar-border))]" />
            )}
            <ul className="space-y-0.5">
              {section.items.map((item) => {
                const badgeValue =
                  item.badge === "critical"
                    ? counts.critical
                    : item.badge === "savings"
                      ? counts.savings
                      : 0;
                const badgeText =
                  item.badge === "critical"
                    ? badgeValue > 0
                      ? badgeValue > 99
                        ? "99+"
                        : String(badgeValue)
                      : null
                    : item.badge === "savings"
                      ? badgeValue > 0
                        ? formatSavings(badgeValue)
                        : null
                      : null;
                const badgeTone =
                  item.badge === "critical"
                    ? "bg-[hsl(var(--severity-critical))] text-white"
                    : "bg-[hsl(var(--success)/0.15)] text-[hsl(var(--success))] border border-[hsl(var(--success)/0.35)]";

                return (
                  <li key={item.to}>
                    <NavLink
                      to={item.to}
                      end={item.end}
                      title={collapsed ? item.label : undefined}
                      className={({ isActive }) =>
                        cn(
                          "group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                          collapsed && "justify-center px-0",
                          isActive
                            ? "bg-[hsl(var(--sidebar-accent))] text-[hsl(var(--sidebar-accent-foreground))]"
                            : "text-[hsl(var(--sidebar-foreground))] hover:bg-[hsl(var(--sidebar-accent)/0.6)] hover:text-[hsl(var(--sidebar-accent-foreground))]",
                        )
                      }
                    >
                      {({ isActive }) => (
                        <>
                          {isActive && !collapsed && (
                            <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-r bg-[hsl(var(--sidebar-active))]" />
                          )}
                          <item.icon className="h-[18px] w-[18px] shrink-0" />
                          {!collapsed && (
                            <>
                              <span className="flex-1 truncate">{item.label}</span>
                              {badgeText && (
                                <span
                                  className={cn(
                                    "inline-flex h-5 min-w-[20px] items-center justify-center rounded-full px-1.5 text-[10px] font-semibold leading-none",
                                    badgeTone,
                                  )}
                                >
                                  {badgeText}
                                </span>
                              )}
                            </>
                          )}
                          {collapsed && badgeText && (
                            <span className="absolute right-1 top-1 flex h-2 w-2 rounded-full bg-[hsl(var(--severity-critical))]" />
                          )}
                        </>
                      )}
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Collapse toggle */}
      <button
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        className="absolute -right-3 top-16 flex h-6 w-6 items-center justify-center rounded-full border border-[hsl(var(--border))] bg-[hsl(var(--card))] text-[hsl(var(--muted-foreground))] shadow-sm transition-colors hover:text-[hsl(var(--foreground))]"
      >
        {collapsed ? <PanelLeftOpen className="h-3.5 w-3.5" /> : <PanelLeftClose className="h-3.5 w-3.5" />}
      </button>

      {/* Footer: Settings · Docs · User */}
      <div className="space-y-1 border-t border-[hsl(var(--sidebar-border))] p-2">
        <NavLink
          to="/settings"
          title={collapsed ? "Settings" : undefined}
          className={({ isActive }) =>
            cn(
              "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
              collapsed && "justify-center px-0",
              isActive
                ? "bg-[hsl(var(--sidebar-accent))] text-[hsl(var(--sidebar-accent-foreground))]"
                : "text-[hsl(var(--sidebar-foreground))] hover:bg-[hsl(var(--sidebar-accent)/0.6)] hover:text-[hsl(var(--sidebar-accent-foreground))]",
            )
          }
        >
          <SettingsIcon className="h-[18px] w-[18px] shrink-0" />
          {!collapsed && <span>Settings</span>}
        </NavLink>
        <a
          href="https://github.com/sandyshd/CloudGuardIQ"
          target="_blank"
          rel="noreferrer"
          title={collapsed ? "Docs" : undefined}
          className={cn(
            "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-[hsl(var(--sidebar-foreground))] transition-colors hover:bg-[hsl(var(--sidebar-accent)/0.6)] hover:text-[hsl(var(--sidebar-accent-foreground))]",
            collapsed && "justify-center px-0",
          )}
        >
          <BookOpen className="h-[18px] w-[18px] shrink-0" />
          {!collapsed && <span>Docs</span>}
        </a>
        <SidebarUser collapsed={collapsed} />
      </div>
    </aside>
  );
}

