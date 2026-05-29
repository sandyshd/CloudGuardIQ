import { HelpCircle, Search } from "lucide-react";
import { Button } from "../ui/button";
import { ScopePill } from "./ScopePill";
import { TimeRangeSelector } from "./TimeRangeSelector";
import { NotificationsMenu } from "./NotificationsMenu";
import { TopbarUser } from "./TopbarUser";

interface Props {
  onOpenPalette: () => void;
  onOpenHelp: () => void;
}

const isMac =
  typeof navigator !== "undefined" && /Mac|iPhone|iPad/i.test(navigator.platform);

export function Topbar({ onOpenPalette, onOpenHelp }: Props) {
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
        <div className="hidden md:flex md:items-center md:gap-2">
          <ScopePill />
          <TimeRangeSelector />
        </div>
        <NotificationsMenu />

        <Button
          variant="ghost"
          size="icon"
          aria-label="Keyboard shortcuts (?)"
          title="Keyboard shortcuts (?)"
          className="h-9 w-9"
          onClick={onOpenHelp}
        >
          <HelpCircle className="h-4 w-4" />
        </Button>
        <TopbarUser />
      </div>
    </header>
  );
}