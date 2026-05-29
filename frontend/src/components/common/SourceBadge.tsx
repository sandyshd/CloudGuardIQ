import { Landmark, ShieldCheck } from "lucide-react";
import { cn } from "../../lib/utils";

/**
 * Finding provenance.
 *
 * ``AZURE_POLICY`` findings are ingested from Microsoft's Azure Policy
 * Regulatory Compliance API (rule_id prefixed ``AZPOL-``). Everything else
 * is produced by CloudGuardIQ's own native rule engine.
 */
export type FindingSource = "AZURE_POLICY" | "NATIVE";

const AZURE_POLICY_PREFIX = "AZPOL-";

/** Classify a finding by its rule_id. */
export function findingSource(ruleId: string | undefined): FindingSource {
  return ruleId?.startsWith(AZURE_POLICY_PREFIX) ? "AZURE_POLICY" : "NATIVE";
}

const sourceConfig: Record<
  FindingSource,
  { label: string; title: string; className: string; Icon: typeof Landmark }
> = {
  AZURE_POLICY: {
    label: "Azure Policy",
    title:
      "Sourced from Microsoft's Azure Policy Regulatory Compliance API — authoritative per-control evaluation.",
    className:
      "border-[hsl(var(--primary)/0.4)] bg-[hsl(var(--primary)/0.08)] text-[hsl(var(--primary))]",
    Icon: Landmark,
  },
  NATIVE: {
    label: "CloudGuardIQ",
    title: "Detected by CloudGuardIQ's native configuration rule engine.",
    className:
      "border-[hsl(var(--border))] bg-[hsl(var(--muted))] text-[hsl(var(--muted-foreground))]",
    Icon: ShieldCheck,
  },
};

/**
 * Badge that makes a finding's origin explicit. By default only renders for
 * Azure Policy findings (the noteworthy case); pass ``showNative`` to also
 * render the CloudGuardIQ-native badge, e.g. on the detail panel header.
 */
export function SourceBadge({
  ruleId,
  showNative = false,
  className,
}: {
  ruleId: string | undefined;
  showNative?: boolean;
  className?: string;
}) {
  const source = findingSource(ruleId);
  if (source === "NATIVE" && !showNative) return null;
  const config = sourceConfig[source];
  const { Icon } = config;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
        config.className,
        className,
      )}
      title={config.title}
    >
      <Icon className="h-3 w-3" />
      {config.label}
    </span>
  );
}
