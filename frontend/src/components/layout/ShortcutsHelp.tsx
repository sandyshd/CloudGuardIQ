import { useEffect } from "react";
import { X } from "lucide-react";

interface Shortcut {
  keys: string[];
  label: string;
}

const SHORTCUTS: { group: string; items: Shortcut[] }[] = [
  {
    group: "Global",
    items: [
      { keys: ["⌘", "K"], label: "Open command palette" },
      { keys: ["?"], label: "Show this help" },
      { keys: ["Esc"], label: "Close dialogs / panels" },
    ],
  },
  {
    group: "Navigation",
    items: [
      { keys: ["g", "f"], label: "Go to Findings" },
      { keys: ["g", "r"], label: "Go to Resources" },
      { keys: ["g", "o"], label: "Go to Overview" },
      { keys: ["g", "c"], label: "Go to Compliance" },
      { keys: ["g", "s"], label: "Go to Settings" },
    ],
  },
  {
    group: "Lists & tables",
    items: [
      { keys: ["j"], label: "Next row" },
      { keys: ["k"], label: "Previous row" },
      { keys: ["↵"], label: "Open active row" },
    ],
  },
];

interface Props {
  open: boolean;
  onClose: () => void;
}

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex min-w-[24px] items-center justify-center rounded border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-1.5 py-0.5 font-mono text-[11px] font-semibold text-[hsl(var(--foreground))]">
      {children}
    </kbd>
  );
}

export function ShortcutsHelp({ open, onClose }: Props) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="shortcuts-title"
      className="fixed inset-0 z-[90] flex items-center justify-center px-4"
    >
      <button
        type="button"
        aria-label="Close shortcuts help"
        onClick={onClose}
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
      />
      <div className="relative z-10 w-full max-w-lg overflow-hidden rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--popover))] shadow-2xl">
        <div className="flex items-center justify-between border-b border-[hsl(var(--border))] px-4 py-3">
          <h2
            id="shortcuts-title"
            className="text-sm font-semibold text-[hsl(var(--foreground))]"
          >
            Keyboard shortcuts
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="rounded p-1 text-[hsl(var(--muted-foreground))] transition-colors hover:bg-[hsl(var(--muted))] hover:text-[hsl(var(--foreground))]"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="max-h-[60vh] overflow-y-auto p-4">
          {SHORTCUTS.map((g) => (
            <section key={g.group} className="mb-4 last:mb-0">
              <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                {g.group}
              </h3>
              <ul className="space-y-1.5">
                {g.items.map((s) => (
                  <li
                    key={s.label}
                    className="flex items-center justify-between gap-3 rounded-md px-2 py-1.5 hover:bg-[hsl(var(--muted)/0.4)]"
                  >
                    <span className="text-sm text-[hsl(var(--foreground))]">
                      {s.label}
                    </span>
                    <span className="flex items-center gap-1">
                      {s.keys.map((k, i) => (
                        <Kbd key={i}>{k}</Kbd>
                      ))}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
        <div className="border-t border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.4)] px-4 py-2 text-[11px] text-[hsl(var(--muted-foreground))]">
          Press <Kbd>?</Kbd> any time to show this help.
        </div>
      </div>
    </div>
  );
}