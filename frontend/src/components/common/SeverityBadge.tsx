import type { Severity } from "../../types";
import { cn } from "../../lib/utils";

const severityStyles: Record<Severity, { dot: string; bg: string; text: string; label: string }> = {
  CRITICAL: {
    dot: "bg-[hsl(var(--severity-critical))]",
    bg: "bg-[hsl(var(--severity-critical)/0.12)]",
    text: "text-[hsl(var(--severity-critical))]",
    label: "Critical",
  },
  HIGH: {
    dot: "bg-[hsl(var(--severity-high))]",
    bg: "bg-[hsl(var(--severity-high)/0.12)]",
    text: "text-[hsl(var(--severity-high))]",
    label: "High",
  },
  MEDIUM: {
    dot: "bg-[hsl(var(--severity-medium))]",
    bg: "bg-[hsl(var(--severity-medium)/0.14)]",
    text: "text-[hsl(var(--severity-medium))]",
    label: "Medium",
  },
  LOW: {
    dot: "bg-[hsl(var(--severity-low))]",
    bg: "bg-[hsl(var(--severity-low)/0.12)]",
    text: "text-[hsl(var(--severity-low))]",
    label: "Low",
  },
  INFORMATIONAL: {
    dot: "bg-[hsl(var(--severity-info))]",
    bg: "bg-[hsl(var(--severity-info)/0.14)]",
    text: "text-[hsl(var(--severity-info))]",
    label: "Info",
  },
};

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const s = severityStyles[severity];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset ring-[hsl(var(--border))]",
        s.bg,
        s.text,
        className,
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", s.dot)} aria-hidden />
      {s.label}
    </span>
  );
}
