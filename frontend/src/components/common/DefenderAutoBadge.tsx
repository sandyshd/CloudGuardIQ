import { Shield } from "lucide-react";
import type { FindingResult } from "../../types";

/**
 * "Defender auto-detected" badge.
 *
 * CloudGuardIQ never requires Microsoft Defender for Cloud — it is always
 * an opportunistic enrichment. When we detect that any scanned resource was
 * captured at TIER2 (Defender free CSPM) or TIER3 (Defender paid plans),
 * we surface this badge to acknowledge the customer's existing investment
 * and to communicate that their findings carry richer signal at no extra
 * charge.
 *
 * Returns ``null`` when no Defender enrichment is detected so the badge is
 * silently absent on Tier 1-only environments.
 */
export function DefenderAutoBadge({ findings }: { findings: FindingResult[] }) {
  const enriched = findings.some((f) => {
    const tier = f.resource_snapshot?.data_tier;
    return tier === "TIER2_FREE_CSPM" || tier === "TIER3_PAID";
  });
  if (!enriched) return null;

  const tier3 = findings.some(
    (f) => f.resource_snapshot?.data_tier === "TIER3_PAID",
  );
  const label = tier3
    ? "Defender for Cloud (paid) detected — findings enriched"
    : "Defender for Cloud (free CSPM) detected — findings enriched";

  return (
    <div
      className="inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-xs font-medium text-emerald-800"
      title="CloudGuardIQ auto-detected Microsoft Defender for Cloud and is using it to enrich your findings at no extra charge."
    >
      <Shield className="h-3.5 w-3.5" />
      <span>{label}</span>
    </div>
  );
}
