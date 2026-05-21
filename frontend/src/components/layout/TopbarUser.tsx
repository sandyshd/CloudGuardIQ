import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { LogOut, Settings as SettingsIcon, Sun, Moon, Monitor } from "lucide-react";
import { useAuth } from "../../hooks/useAuth";
import { useTheme } from "./ThemeProvider";
import { cn } from "../../lib/utils";

function initial(name?: string | null): string {
  return (name || "U").trim().charAt(0).toUpperCase() || "U";
}

export function TopbarUser() {
  const { user, logout } = useAuth();
  const { theme, setTheme } = useTheme();
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
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

  if (!user) return null;

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-label="Account menu"
        aria-expanded={open}
        className="flex items-center gap-2 rounded-md px-1.5 py-1 transition-colors hover:bg-[hsl(var(--accent)/0.15)]"
      >
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[hsl(var(--primary))] to-[hsl(var(--accent))] text-xs font-semibold text-white">
          {initial(user.name)}
        </span>
        <span className="hidden max-w-[140px] truncate text-sm font-medium text-[hsl(var(--foreground))] md:inline">
          {user.name}
        </span>
      </button>

      {open && (
        <div className="absolute right-0 top-[calc(100%+6px)] z-40 w-60 overflow-hidden rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] shadow-xl">
          <div className="border-b border-[hsl(var(--border))] px-3 py-2.5">
            <div className="truncate text-sm font-medium text-[hsl(var(--foreground))]">
              {user.name}
            </div>
            <div className="truncate text-xs text-[hsl(var(--muted-foreground))]">
              {user.email || ""}
            </div>
          </div>
          <div className="border-b border-[hsl(var(--border))] py-1">
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                navigate("/settings");
              }}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent)/0.15)]"
            >
              <SettingsIcon className="h-4 w-4" />
              Settings
            </button>
          </div>
          <div className="border-b border-[hsl(var(--border))] px-3 py-2">
            <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
              Theme
            </div>
            <div className="grid grid-cols-3 gap-1">
              {[
                { id: "light" as const, label: "Light", icon: Sun },
                { id: "dark" as const, label: "Dark", icon: Moon },
                { id: "system" as const, label: "Auto", icon: Monitor },
              ].map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setTheme(opt.id)}
                  className={cn(
                    "flex flex-col items-center gap-1 rounded-md border px-2 py-1.5 text-[11px] transition-colors",
                    theme === opt.id
                      ? "border-[hsl(var(--primary)/0.5)] bg-[hsl(var(--primary)/0.08)] text-[hsl(var(--primary))]"
                      : "border-[hsl(var(--border))] text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent)/0.15)] hover:text-[hsl(var(--foreground))]",
                  )}
                >
                  <opt.icon className="h-3.5 w-3.5" />
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
          <button
            type="button"
            onClick={() => {
              setOpen(false);
              logout();
            }}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--severity-critical)/0.1)] hover:text-[hsl(var(--severity-critical))]"
          >
            <LogOut className="h-4 w-4" />
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}
