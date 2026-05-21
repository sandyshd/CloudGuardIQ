import { Shield } from "lucide-react";
import type { CloudProvider, FindingResult } from "../../types";
import { TIER2_VALUES, TIER3_VALUES } from "../../types";

/**
 * Cloud-agnostic enrichment badge.
 *
 * CloudGuardIQ never requires a vendor security service — those signals
 * are always opportunistic enrichment. When we detect that scanned
 * resources were captured at TIER2 (free vendor CSPM) or TIER3 (paid
 * deep telemetry), we surface this badge to acknowledge the customer's
 * existing investment and to communicate that their findings carry
 * richer signal at no extra charge.
 *
 * The vendor is inferred from the resource's CloudProvider, so the badge
 * renders correctly across Azure, AWS, and GCP without code changes.
 *
 * Returns ``null`` when no Tier 2/3 enrichment is detected so the badge is
 * silently absent on Tier 1-only environments.
 */

const VENDOR_LABEL: Record<CloudProvider, { tier2: string; tier3: string }> = {
  AZURE: {
    tier2: "Defender for Cloud (free CSPM)",
    tier3: "Defender for Cloud (paid)",
  },
  AWS: {
    tier2: "AWS Security Hub",
    tier3: "GuardDuty / Inspector",
  },
  GCP: {
    tier2: "Security Command Center",
    tier3: "SCC Premium",
  },
  TERRAFORM: {
    tier2: "Static analysis",
    tier3: "Static analysis",
  },
};

export function DefenderAutoBadge({ findings }: { findings: FindingResult[] }) {
  const enriched = findings.find((f) => {
    const t = f.resource_snapshot?.data_tier;
    return t !== undefined && (TIER2_VALUES.includes(t) || TIER3_VALUES.includes(t));
  });
  if (!enriched || !enriched.resource_snapshot) return null;

  const provider: CloudProvider = enriched.resource_snapshot.provider;
  const tier3 = findings.some((f) => {
    const t = f.resource_snapshot?.data_tier;
    return t !== undefined && TIER3_VALUES.includes(t);
  });
  const vendor = VENDOR_LABEL[provider];
  const label = `${tier3 ? vendor.tier3 : vendor.tier2} detected — findings enriched`;

  return (
    <div
      className="inline-flex items-center gap-2 rounded-full border border-[hsl(var(--success)/0.4)] bg-[hsl(var(--success)/0.08)] px-3 py-1 text-xs font-medium text-[hsl(var(--success))]"
      title="CloudGuardIQ auto-detected your cloud's native security service and is using it to enrich findings at no extra charge."
    >
      <Shield className="h-3.5 w-3.5" />
      <span>{label}</span>
    </div>
  );
}

