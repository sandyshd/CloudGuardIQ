import type { DataTier } from "../../types";
import { cn } from "../../lib/utils";
import { useState } from "react";

const tierConfig: Record<
  DataTier,
  { label: string; className: string; tooltip: string }
> = {
  TIER1_NATIVE: {
    label: "T1",
    className: "bg-[hsl(var(--muted))] text-[hsl(var(--muted-foreground))]",
    tooltip: "T1: Native config scan only",
  },
  TIER2_FREE_CSPM: {
    label: "T2",
    className: "bg-[hsl(var(--warning)/0.14)] text-[hsl(var(--warning))]",
    tooltip: "T2: + Vendor CSPM enrichment (free)",
  },
  TIER2_ENRICHED: {
    label: "T2",
    className: "bg-[hsl(var(--warning)/0.14)] text-[hsl(var(--warning))]",
    tooltip: "T2: + Vendor CSPM enrichment (free)",
  },
  TIER3_PAID: {
    label: "T3",
    className: "bg-[hsl(var(--success)/0.14)] text-[hsl(var(--success))]",
    tooltip: "T3: + Deep threat intel (paid vendor plan)",
  },
  TIER3_DEEP: {
    label: "T3",
    className: "bg-[hsl(var(--success)/0.14)] text-[hsl(var(--success))]",
    tooltip: "T3: + Deep threat intel (paid vendor plan)",
  },
};

export function DataTierBadge({ tier }: { tier: DataTier }) {
  const [show, setShow] = useState(false);
  const config = tierConfig[tier];

  return (
    <span
      className="relative inline-block"
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
      onFocus={() => setShow(true)}
      onBlur={() => setShow(false)}
    >
      <span
        className={cn(
          "inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
          config.className,
        )}
      >
        {config.label}
      </span>
      {show && (
        <span
          role="tooltip"
          className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-1 -translate-x-1/2 whitespace-nowrap rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-2 py-1 text-xs text-[hsl(var(--foreground))] shadow-lg"
        >
          {config.tooltip}
        </span>
      )}
    </span>
  );
}
