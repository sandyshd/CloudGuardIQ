import { useEffect, useState } from "react";
import { useAuth } from "../../hooks/useAuth";
import { Button } from "../ui/button";
import { Bell, LogOut, Search, Sun, Moon, Monitor } from "lucide-react";
import { SubscriptionSwitcher } from "./SubscriptionSwitcher";
import { useTheme } from "./ThemeProvider";

export function Topbar() {
  const { user, logout } = useAuth();
  const { theme, setTheme } = useTheme();
  const [showThemeMenu, setShowThemeMenu] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);

  // Cmd/Ctrl+K focuses the search field. Real palette is a future iteration.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        const el = document.getElementById("global-search");
        if (el) (el as HTMLInputElement).focus();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const ThemeIcon = theme === "dark" ? Moon : theme === "light" ? Sun : Monitor;

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-[hsl(var(--border))] bg-[hsl(var(--background)/0.85)] px-6 backdrop-blur-md">
      {/* Search */}
      <div className="relative flex-1 max-w-xl">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
        <input
          id="global-search"
          type="search"
          placeholder="Search resources, findings, policies..."
          className="h-9 w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--card))] pl-9 pr-16 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
        />
        <kbd className="pointer-events-none absolute right-2 top-1/2 hidden -translate-y-1/2 items-center gap-0.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-1.5 py-0.5 text-[10px] font-medium text-[hsl(var(--muted-foreground))] sm:inline-flex">
          ⌘K
        </kbd>
      </div>

      <div className="ml-auto flex items-center gap-2">
        <SubscriptionSwitcher />

        {/* Notifications */}
        <Button variant="ghost" size="icon" aria-label="Notifications" className="relative h-9 w-9">
          <Bell className="h-4 w-4" />
          <span className="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-[hsl(var(--severity-critical))]" />
        </Button>

        {/* Theme switcher */}
        <div className="relative">
          <Button
            variant="ghost"
            size="icon"
            aria-label="Theme"
            className="h-9 w-9"
            onClick={() => setShowThemeMenu((v) => !v)}
          >
            <ThemeIcon className="h-4 w-4" />
          </Button>
          {showThemeMenu && (
            <div
              className="absolute right-0 top-10 w-36 overflow-hidden rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] shadow-lg"
              onMouseLeave={() => setShowThemeMenu(false)}
            >
              {[
                { id: "light" as const, label: "Light", icon: Sun },
                { id: "dark" as const, label: "Dark", icon: Moon },
                { id: "system" as const, label: "System", icon: Monitor },
              ].map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => {
                    setTheme(opt.id);
                    setShowThemeMenu(false);
                  }}
                  className={`flex w-full items-center gap-2 px-3 py-2 text-left text-sm transition-colors hover:bg-[hsl(var(--accent)/0.15)] ${
                    theme === opt.id ? "text-[hsl(var(--primary))]" : "text-[hsl(var(--foreground))]"
                  }`}
                >
                  <opt.icon className="h-4 w-4" />
                  {opt.label}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* User menu */}
        {user && (
          <div className="relative">
            <button
              type="button"
              onClick={() => setShowUserMenu((v) => !v)}
              className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors hover:bg-[hsl(var(--accent)/0.15)]"
            >
              <span className="flex h-7 w-7 items-center justify-center rounded-full bg-gradient-to-br from-[hsl(var(--primary))] to-[hsl(var(--accent))] text-xs font-semibold text-white">
                {(user.name || "U").trim().charAt(0).toUpperCase()}
              </span>
              <span className="hidden max-w-[140px] truncate font-medium md:inline">{user.name}</span>
            </button>
            {showUserMenu && (
              <div
                className="absolute right-0 top-10 w-56 overflow-hidden rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] shadow-lg"
                onMouseLeave={() => setShowUserMenu(false)}
              >
                <div className="border-b border-[hsl(var(--border))] px-3 py-2.5">
                  <div className="truncate text-sm font-medium">{user.name}</div>
                  <div className="truncate text-xs text-[hsl(var(--muted-foreground))]">
                    {user.email || ""}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={logout}
                  className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent)/0.15)]"
                >
                  <LogOut className="h-4 w-4" />
                  Sign out
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </header>
  );
}

