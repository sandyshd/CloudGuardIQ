import type { DataTier } from "../../types";
import { cn } from "../../lib/utils";
import { useState } from "react";

const tierConfig: Record<DataTier, { label: string; color: string; tooltip: string }> = {
  TIER1_NATIVE: {
    label: "T1",
    color: "bg-gray-200 text-gray-700",
    tooltip: "T1: Config scan only",
  },
  TIER2_FREE_CSPM: {
    label: "T2",
    color: "bg-amber-100 text-amber-800",
    tooltip: "T2: + Defender CSPM (free)",
  },
  TIER3_PAID: {
    label: "T3",
    color: "bg-emerald-100 text-emerald-800",
    tooltip: "T3: + Full threat intel",
  },
};

export function DataTierBadge({ tier }: { tier: DataTier }) {
  const [showTooltip, setShowTooltip] = useState(false);
  const config = tierConfig[tier];

  return (
    <span
      className="relative inline-block"
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <span
        className={cn(
          "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold",
          config.color
        )}
      >
        {config.label}
      </span>
      {showTooltip && (
        <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 whitespace-nowrap rounded bg-gray-900 px-2 py-1 text-xs text-white shadow-lg z-50">
          {config.tooltip}
        </span>
      )}
    </span>
  );
}