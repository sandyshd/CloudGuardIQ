import { useEffect, useRef, useState } from "react";
import { Calendar, ChevronDown } from "lucide-react";
import { useTimeRange, type TimeRangeId } from "../../contexts/TimeRangeContext";
import { cn } from "../../lib/utils";

const PRESETS: { id: Exclude<TimeRangeId, "custom">; label: string }[] = [
  { id: "24h", label: "Last 24 hours" },
  { id: "7d", label: "Last 7 days" },
  { id: "30d", label: "Last 30 days" },
  { id: "90d", label: "Last 90 days" },
];

const SHORT_LABEL: Record<TimeRangeId, string> = {
  "24h": "24h",
  "7d": "7d",
  "30d": "30d",
  "90d": "90d",
  custom: "Custom",
};

function fmt(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export function TimeRangeSelector() {
  const { range, setRangeId, setCustomRange } = useTimeRange();
  const [open, setOpen] = useState(false);
  const [from, setFrom] = useState(fmt(range.from));
  const [to, setTo] = useState(fmt(range.to));
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setFrom(fmt(range.from));
    setTo(fmt(range.to));
  }, [range.from, range.to]);

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

  const applyCustom = () => {
    const f = new Date(from);
    const t = new Date(to);
    if (Number.isNaN(f.getTime()) || Number.isNaN(t.getTime()) || f > t) return;
    setCustomRange(f, t);
    setOpen(false);
  };

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="inline-flex h-9 items-center gap-1.5 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-2.5 text-xs font-medium text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent)/0.1)]"
      >
        <Calendar className="h-3.5 w-3.5 text-[hsl(var(--muted-foreground))]" />
        <span>{SHORT_LABEL[range.id]}</span>
        <ChevronDown className="h-3 w-3 text-[hsl(var(--muted-foreground))]" />
      </button>

      {open && (
        <div className="absolute right-0 top-[calc(100%+6px)] z-40 w-64 overflow-hidden rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] shadow-xl">
          <ul className="py-1">
            {PRESETS.map((p) => {
              const active = range.id === p.id;
              return (
                <li key={p.id}>
                  <button
                    type="button"
                    onClick={() => {
                      setRangeId(p.id);
                      setOpen(false);
                    }}
                    className={cn(
                      "flex w-full items-center justify-between px-3 py-2 text-left text-sm transition-colors",
                      active
                        ? "bg-[hsl(var(--primary)/0.08)] text-[hsl(var(--primary))]"
                        : "text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent)/0.15)]",
                    )}
                  >
                    {p.label}
                    {active && <span className="text-[10px] uppercase tracking-wider">active</span>}
                  </button>
                </li>
              );
            })}
          </ul>
          <div className="border-t border-[hsl(var(--border))] p-3">
            <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
              Custom range
            </div>
            <div className="grid grid-cols-2 gap-2">
              <input
                type="date"
                value={from}
                onChange={(e) => setFrom(e.target.value)}
                className="h-8 rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--card))] px-2 text-xs text-[hsl(var(--foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
              />
              <input
                type="date"
                value={to}
                onChange={(e) => setTo(e.target.value)}
                className="h-8 rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--card))] px-2 text-xs text-[hsl(var(--foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
              />
            </div>
            <button
              type="button"
              onClick={applyCustom}
              className="mt-2 h-8 w-full rounded-md bg-[hsl(var(--primary))] text-xs font-medium text-[hsl(var(--primary-foreground))] transition-colors hover:bg-[hsl(var(--primary)/0.9)]"
            >
              Apply
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
