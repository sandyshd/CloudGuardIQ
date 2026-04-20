import type { DataTier } from "../../types";
import { cn } from "../../lib/utils";

const tierLabels: Record<DataTier, string> = {
  TIER1_NATIVE: "Tier 1",
  TIER2_FREE_CSPM: "Tier 2",
  TIER3_PAID: "Tier 3",
};

const tierColors: Record<DataTier, string> = {
  TIER1_NATIVE: "bg-emerald-100 text-emerald-800",
  TIER2_FREE_CSPM: "bg-blue-100 text-blue-800",
  TIER3_PAID: "bg-purple-100 text-purple-800",
};

export function DataTierBadge({ tier }: { tier: DataTier }) {
  return (
    <span className={cn("inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium", tierColors[tier])}>
      {tierLabels[tier]}
    </span>
  );
}
