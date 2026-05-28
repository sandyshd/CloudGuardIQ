import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

export type TimeRangeId = "24h" | "7d" | "30d" | "90d" | "custom";

export interface TimeRange {
  id: TimeRangeId;
  label: string;
  from: Date;
  to: Date;
}

interface TimeRangeContextValue {
  range: TimeRange;
  setRangeId: (id: TimeRangeId) => void;
  setCustomRange: (from: Date, to: Date) => void;
}

const STORAGE_KEY = "cguardiq.timeRange";

const PRESETS: Record<Exclude<TimeRangeId, "custom">, { label: string; ms: number }> = {
  "24h": { label: "Last 24 hours", ms: 24 * 60 * 60 * 1000 },
  "7d": { label: "Last 7 days", ms: 7 * 24 * 60 * 60 * 1000 },
  "30d": { label: "Last 30 days", ms: 30 * 24 * 60 * 60 * 1000 },
  "90d": { label: "Last 90 days", ms: 90 * 24 * 60 * 60 * 1000 },
};

function buildPreset(id: Exclude<TimeRangeId, "custom">): TimeRange {
  const to = new Date();
  const from = new Date(to.getTime() - PRESETS[id].ms);
  return { id, label: PRESETS[id].label, from, to };
}

const Ctx = createContext<TimeRangeContextValue | null>(null);

export function TimeRangeProvider({ children }: { children: ReactNode }) {
  const [range, setRange] = useState<TimeRange>(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as { id: TimeRangeId; from?: string; to?: string };
        if (parsed.id === "custom" && parsed.from && parsed.to) {
          return {
            id: "custom",
            label: "Custom range",
            from: new Date(parsed.from),
            to: new Date(parsed.to),
          };
        }
        if (parsed.id in PRESETS) {
          return buildPreset(parsed.id as Exclude<TimeRangeId, "custom">);
        }
      }
    } catch {
      /* ignore */
    }
    return buildPreset("90d");
  });

  const persist = useCallback((r: TimeRange) => {
    try {
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ id: r.id, from: r.from.toISOString(), to: r.to.toISOString() }),
      );
    } catch {
      /* ignore */
    }
  }, []);

  const setRangeId = useCallback(
    (id: TimeRangeId) => {
      if (id === "custom") return;
      const next = buildPreset(id);
      setRange(next);
      persist(next);
    },
    [persist],
  );

  const setCustomRange = useCallback(
    (from: Date, to: Date) => {
      const next: TimeRange = { id: "custom", label: "Custom range", from, to };
      setRange(next);
      persist(next);
    },
    [persist],
  );

  useEffect(() => {
    if (range.id === "custom") return;
    const id = window.setInterval(() => {
      setRange((r) => (r.id === "custom" ? r : buildPreset(r.id)));
    }, 5 * 60 * 1000);
    return () => window.clearInterval(id);
  }, [range.id]);

  const value = useMemo(
    () => ({ range, setRangeId, setCustomRange }),
    [range, setRangeId, setCustomRange],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTimeRange(): TimeRangeContextValue {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useTimeRange must be used inside TimeRangeProvider");
  return ctx;
}
