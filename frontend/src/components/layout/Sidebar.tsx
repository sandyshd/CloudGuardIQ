import { useState, useMemo } from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  ShieldAlert,
  Sparkles,
  TrendingUp,
  ClipboardCheck,
  HeartPulse,
  Settings as SettingsIcon,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
} from "lucide-react";
import { cn } from "../../lib/utils";

interface NavItem {
  to: string;
  icon: typeof LayoutDashboard;
  label: string;
  end?: boolean;
}

interface NavSection {
  label: string;
  items: NavItem[];
}

const sections: NavSection[] = [
  {
    label: "Posture",
    items: [
      { to: "/", icon: LayoutDashboard, label: "Overview", end: true },
      { to: "/findings", icon: ShieldAlert, label: "Findings" },
      { to: "/ai-fix", icon: Sparkles, label: "AI Remediation" },
      { to: "/compliance", icon: ClipboardCheck, label: "Compliance" },
    ],
  },
  {
    label: "FinOps",
    items: [{ to: "/finops", icon: TrendingUp, label: "Cost Governance" }],
  },
  {
    label: "Platform",
    items: [
      { to: "/self-heal", icon: HeartPulse, label: "Self-Healing" },
      { to: "/settings", icon: SettingsIcon, label: "Settings" },
    ],
  },
];

const STORAGE_KEY = "cguardiq.sidebarCollapsed";

export function Sidebar() {
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) === "1";
    } catch {
      return false;
    }
  });

  const width = collapsed ? "w-[68px]" : "w-[248px]";

  const toggle = () => {
    setCollapsed((c) => {
      const next = !c;
      try {
        localStorage.setItem(STORAGE_KEY, next ? "1" : "0");
      } catch {
        /* ignore */
      }
      return next;
    });
  };

  const renderedSections = useMemo(() => sections, []);

  return (
    <aside
      className={cn(
        "relative flex h-screen flex-col border-r border-[hsl(var(--sidebar-border))] bg-[hsl(var(--sidebar-background))] text-[hsl(var(--sidebar-foreground))] transition-[width] duration-200 ease-out",
        width,
      )}
    >
      {/* Brand */}
      <div className="flex h-14 items-center gap-2.5 border-b border-[hsl(var(--sidebar-border))] px-4">
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

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-2 py-4">
        {renderedSections.map((section) => (
          <div key={section.label} className="mb-5 last:mb-0">
            {!collapsed && (
              <div className="px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--sidebar-muted))]">
                {section.label}
              </div>
            )}
            <ul className="space-y-0.5">
              {section.items.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.end}
                    title={collapsed ? item.label : undefined}
                    className={({ isActive }) =>
                      cn(
                        "group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                        isActive
                          ? "bg-[hsl(var(--sidebar-accent))] text-[hsl(var(--sidebar-accent-foreground))]"
                          : "text-[hsl(var(--sidebar-foreground))] hover:bg-[hsl(var(--sidebar-accent)/0.6)] hover:text-[hsl(var(--sidebar-accent-foreground))]",
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && (
                          <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-r bg-[hsl(var(--sidebar-active))]" />
                        )}
                        <item.icon className="h-[18px] w-[18px] shrink-0" />
                        {!collapsed && <span className="truncate">{item.label}</span>}
                      </>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      {/* Collapse toggle */}
      <button
        type="button"
        onClick={toggle}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        className="absolute -right-3 top-16 flex h-6 w-6 items-center justify-center rounded-full border border-[hsl(var(--border))] bg-[hsl(var(--card))] text-[hsl(var(--muted-foreground))] shadow-sm transition-colors hover:text-[hsl(var(--foreground))]"
      >
        {collapsed ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronLeft className="h-3.5 w-3.5" />}
      </button>

      {/* Footer */}
      <div className="border-t border-[hsl(var(--sidebar-border))] p-3 text-[11px] text-[hsl(var(--sidebar-muted))]">
        {!collapsed ? (
          <div className="flex items-center justify-between">
            <span>v0.1</span>
            <span className="inline-flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-[hsl(var(--success))]" />
              Healthy
            </span>
          </div>
        ) : (
          <div className="flex justify-center">
            <span className="h-1.5 w-1.5 rounded-full bg-[hsl(var(--success))]" />
          </div>
        )}
      </div>
    </aside>
  );
}
