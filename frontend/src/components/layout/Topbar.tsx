import { useEffect, useState } from "react";
import { HelpCircle, Search } from "lucide-react";
import { Button } from "../ui/button";
import { ScopePill } from "./ScopePill";
import { TimeRangeSelector } from "./TimeRangeSelector";
import { NotificationsMenu } from "./NotificationsMenu";
import { TopbarUser } from "./TopbarUser";

interface Props {
  onOpenPalette: () => void;
}

const isMac =
  typeof navigator !== "undefined" && /Mac|iPhone|iPad/i.test(navigator.platform);

export function Topbar({ onOpenPalette }: Props) {
  const [showHelp, setShowHelp] = useState(false);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onOpenPalette();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onOpenPalette]);

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-[hsl(var(--border))] bg-[hsl(var(--background)/0.85)] px-4 backdrop-blur-md md:px-6">
      {/* Global search trigger (opens command palette) */}
      <button
        type="button"
        onClick={onOpenPalette}
        aria-label="Open command palette"
        className="group flex h-9 w-full max-w-md items-center gap-2 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 text-sm text-[hsl(var(--muted-foreground))] transition-colors hover:border-[hsl(var(--primary)/0.4)] hover:bg-[hsl(var(--accent)/0.05)]"
      >
        <Search className="h-4 w-4" />
        <span className="flex-1 truncate text-left">
          Search resources, findings, policies…
        </span>
        <kbd className="hidden items-center gap-0.5 rounded border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-1.5 py-0.5 text-[10px] font-medium sm:inline-flex">
          {isMac ? "⌘" : "Ctrl"}K
        </kbd>
      </button>

      <div className="ml-auto flex items-center gap-2">
        <ScopePill />
        <TimeRangeSelector />
        <NotificationsMenu />

        {/* Help */}
        <div className="relative">
          <Button
            variant="ghost"
            size="icon"
            aria-label="Help"
            className="h-9 w-9"
            onClick={() => setShowHelp((v) => !v)}
          >
            <HelpCircle className="h-4 w-4" />
          </Button>
          {showHelp && (
            <div
              className="absolute right-0 top-10 w-64 overflow-hidden rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] shadow-xl"
              onMouseLeave={() => setShowHelp(false)}
            >
              <div className="border-b border-[hsl(var(--border))] px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                Help &amp; resources
              </div>
              <a
                href="https://github.com/sandyshd/CloudGuardIQ"
                target="_blank"
                rel="noreferrer"
                className="block px-3 py-2 text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent)/0.15)]"
              >
                Documentation
              </a>
              <button
                type="button"
                onClick={() => {
                  setShowHelp(false);
                  onOpenPalette();
                }}
                className="block w-full px-3 py-2 text-left text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent)/0.15)]"
              >
                Open command palette
                <span className="float-right text-[10px] text-[hsl(var(--muted-foreground))]">
                  {isMac ? "⌘K" : "Ctrl+K"}
                </span>
              </button>
              <a
                href="https://github.com/sandyshd/CloudGuardIQ/issues/new"
                target="_blank"
                rel="noreferrer"
                className="block border-t border-[hsl(var(--border))] px-3 py-2 text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent)/0.15)]"
              >
                Report an issue
              </a>
            </div>
          )}
        </div>
        <TopbarUser />

      </div>
    </header>
  );
}

