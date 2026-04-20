import type { Severity } from "../../types";
import { cn } from "../../lib/utils";

const severityColors: Record<Severity, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-blue-500 text-white",
  INFORMATIONAL: "bg-gray-400 text-white",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={cn("inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold", severityColors[severity])}>
      {severity}
    </span>
  );
}
