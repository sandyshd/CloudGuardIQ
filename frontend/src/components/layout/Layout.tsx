import { useState } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { DemoBanner } from "./DemoBanner";
import { CommandPalette } from "./CommandPalette";
import { TimeRangeProvider } from "../../contexts/TimeRangeContext";

export function Layout() {
  const [paletteOpen, setPaletteOpen] = useState(false);

  return (
    <TimeRangeProvider>
      <div className="flex h-screen overflow-hidden bg-[hsl(var(--background))]">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
          <Topbar onOpenPalette={() => setPaletteOpen(true)} />
          <DemoBanner />
          <main className="flex-1 overflow-y-auto">
            <div className="w-full px-6 py-6 lg:px-8">
              <Outlet />
            </div>
          </main>
        </div>
        <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
      </div>
    </TimeRangeProvider>
  );
}
