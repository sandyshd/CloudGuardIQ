import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Shield,
  Sparkles,
  DollarSign,
  ClipboardCheck,
  HeartPulse,
  Settings,
} from "lucide-react";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/findings", icon: Shield, label: "Findings" },
  { to: "/ai-fix", icon: Sparkles, label: "AI Fix" },
  { to: "/finops", icon: DollarSign, label: "FinOps" },
  { to: "/compliance", icon: ClipboardCheck, label: "Compliance" },
  { to: "/self-heal", icon: HeartPulse, label: "Self-Heal" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

export function Sidebar() {
  return (
    <aside className="flex h-screen w-64 flex-col border-r bg-[hsl(var(--sidebar-background))]">
      <div className="flex h-16 items-center gap-2 border-b px-6">
        <Shield className="h-6 w-6 text-[hsl(var(--primary))]" />
        <span className="text-lg font-bold">CloudGuardIQ</span>
      </div>
      <nav className="flex-1 space-y-1 p-4">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                isActive
                  ? "bg-[hsl(var(--sidebar-accent))] text-[hsl(var(--sidebar-accent-foreground))]"
                  : "text-[hsl(var(--sidebar-foreground))] hover:bg-[hsl(var(--sidebar-accent))]"
              }`
            }
          >
            <item.icon className="h-4 w-4" />
            {item.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
