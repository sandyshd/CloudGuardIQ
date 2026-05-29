import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  ShieldAlert,
  TrendingUp,
  ClipboardCheck,
  Settings as SettingsIcon,
} from "lucide-react";
import { cn } from "../../lib/utils";

const ITEMS = [
  { to: "/", icon: LayoutDashboard, label: "Overview", end: true },
  { to: "/findings", icon: ShieldAlert, label: "Findings" },
  { to: "/finops", icon: TrendingUp, label: "Cost" },
  { to: "/compliance", icon: ClipboardCheck, label: "Compliance" },
  { to: "/settings", icon: SettingsIcon, label: "Settings" },
];

/**
 * Read-only mobile bottom navigation. The full Sidebar is hidden under md;
 * this surface provides minimal navigation between the KPIs / findings views
 * that are functional on mobile.
 */
export function MobileBottomNav() {
  return (
    <nav
      aria-label="Primary"
      className="sticky bottom-0 z-30 flex h-14 items-stretch border-t border-[hsl(var(--border))] bg-[hsl(var(--background)/0.95)] backdrop-blur md:hidden"
    >
      {ITEMS.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={({ isActive }) =>
            cn(
              "flex flex-1 flex-col items-center justify-center gap-0.5 px-1 text-[10px] font-medium transition-colors",
              isActive
                ? "text-[hsl(var(--primary))]"
                : "text-[hsl(var(--muted-foreground))]",
            )
          }
        >
          <item.icon className="h-5 w-5" aria-hidden />
          <span>{item.label}</span>
        </NavLink>
      ))}
    </nav>
  );
}