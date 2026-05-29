import { useState } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { DemoBanner } from "./DemoBanner";
import { CommandPalette } from "./CommandPalette";
import { ShortcutsHelp } from "./ShortcutsHelp";
import { MobileBottomNav } from "./MobileBottomNav";
import { TimeRangeProvider } from "../../contexts/TimeRangeContext";
import { useGlobalShortcuts } from "../../hooks/useGlobalShortcuts";

export function Layout() {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  useGlobalShortcuts({
    onOpenPalette: () => setPaletteOpen(true),
    onOpenHelp: () => setHelpOpen(true),
  });

  return (
    <TimeRangeProvider>
      <div className="flex h-screen overflow-hidden bg-[hsl(var(--background))]">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
          <Topbar
            onOpenPalette={() => setPaletteOpen(true)}
            onOpenHelp={() => setHelpOpen(true)}
          />
          <DemoBanner />
          <main className="flex-1 overflow-y-auto">
            <div className="w-full px-4 py-5 sm:px-6 sm:py-6 lg:px-8">
              <Outlet />
            </div>
          </main>
          <MobileBottomNav />
        </div>
        <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
        <ShortcutsHelp open={helpOpen} onClose={() => setHelpOpen(false)} />
      </div>
    </TimeRangeProvider>
  );
}