import type { CloudProvider } from "../../types";

/**
 * Compact cloud-provider chip. Renders the provider name + a colour
 * accent matching the vendor brand so multi-cloud Subscription rows
 * are scannable at a glance.
 */
const STYLE: Record<CloudProvider, { label: string; cls: string }> = {
  AZURE: {
    label: "Azure",
    cls: "border-[hsl(210_100%_50%/0.4)] bg-[hsl(210_100%_50%/0.10)] text-[hsl(210_100%_45%)]",
  },
  AWS: {
    label: "AWS",
    cls: "border-[hsl(36_100%_45%/0.4)] bg-[hsl(36_100%_45%/0.10)] text-[hsl(36_100%_40%)]",
  },
  GCP: {
    label: "GCP",
    cls: "border-[hsl(0_85%_55%/0.4)] bg-[hsl(0_85%_55%/0.10)] text-[hsl(0_85%_50%)]",
  },
  TERRAFORM: {
    label: "Terraform",
    cls: "border-[hsl(265_60%_55%/0.4)] bg-[hsl(265_60%_55%/0.10)] text-[hsl(265_60%_50%)]",
  },
};

export function ProviderBadge({ provider }: { provider?: CloudProvider }) {
  const p: CloudProvider = provider ?? "AZURE";
  const { label, cls } = STYLE[p];
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${cls}`}
      title={`${label} subscription`}
    >
      {label}
    </span>
  );
}
