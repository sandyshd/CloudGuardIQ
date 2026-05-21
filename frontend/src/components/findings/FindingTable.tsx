import { useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../ui/table";
import { SeverityBadge } from "../common/SeverityBadge";
import { DataTierBadge } from "../common/DataTierBadge";
import { Badge } from "../ui/badge";
import { ChevronRight, Copy, Check } from "lucide-react";
import { cn } from "../../lib/utils";
import type { FindingResult, Severity, FindingStatus } from "../../types";

interface FindingTableProps {
  findings: FindingResult[];
  onSelect: (finding: FindingResult) => void;
}

const severityRail: Record<Severity, string> = {
  CRITICAL: "bg-[hsl(var(--severity-critical))]",
  HIGH: "bg-[hsl(var(--severity-high))]",
  MEDIUM: "bg-[hsl(var(--severity-medium))]",
  LOW: "bg-[hsl(var(--severity-low))]",
  INFORMATIONAL: "bg-[hsl(var(--severity-info))]",
};

const statusVariant: Record<FindingStatus, "secondary" | "success" | "warning" | "default"> = {
  OPEN: "warning",
  RESOLVED: "success",
  SNOOZED: "secondary",
  APPLIED: "default",
};

function ResourceIdMono({ id, name }: { id?: string; name: string }) {
  const [copied, setCopied] = useState(false);
  if (!id) return <span className="font-medium text-[hsl(var(--foreground))]">{name}</span>;
  const onCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(id);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <div className="flex flex-col gap-0.5 min-w-0">
      <span className="truncate font-medium text-[hsl(var(--foreground))]">{name}</span>
      <span className="flex items-center gap-1.5 text-[11px] text-[hsl(var(--muted-foreground))]">
        <code className="truncate font-mono">{id.split("/").slice(-2).join("/")}</code>
        <button
          type="button"
          onClick={onCopy}
          aria-label="Copy resource id"
          className="rounded p-0.5 text-[hsl(var(--muted-foreground))] transition-colors hover:bg-[hsl(var(--muted))] hover:text-[hsl(var(--foreground))]"
          title={id}
        >
          {copied ? <Check className="h-3 w-3 text-[hsl(var(--success))]" /> : <Copy className="h-3 w-3" />}
        </button>
      </span>
    </div>
  );
}

export function FindingTable({ findings, onSelect }: FindingTableProps) {
  if (findings.length === 0) {
    return (
      <div className="overflow-hidden rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))]">
        <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
          <div className="text-sm font-medium text-[hsl(var(--foreground))]">No findings match these filters</div>
          <div className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
            Try clearing severity, type, or status filters above.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))]">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[1px] p-0" aria-hidden />
            <TableHead className="min-w-[220px]">Resource</TableHead>
            <TableHead className="min-w-[260px]">Finding</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Tier</TableHead>
            <TableHead className="text-right">Waste / mo</TableHead>
            <TableHead className="text-right">Priority</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="w-8" aria-label="Open" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {findings.map((f) => {
            const status = (f.status ?? "OPEN") as FindingStatus;
            return (
              <TableRow
                key={f.finding_id}
                className="group cursor-pointer"
                onClick={() => onSelect(f)}
              >
                <TableCell className="w-[3px] p-0">
                  <span
                    className={cn(
                      "block h-full min-h-[44px] w-[3px]",
                      severityRail[f.severity],
                    )}
                    aria-hidden
                  />
                </TableCell>
                <TableCell className="max-w-[260px]">
                  <ResourceIdMono
                    id={f.resource_snapshot?.id}
                    name={f.resource_snapshot?.resource_name || "—"}
                  />
                </TableCell>
                <TableCell className="max-w-[360px]">
                  <div className="truncate text-[13px] font-medium text-[hsl(var(--foreground))]">
                    {f.rule_name || f.rule_id}
                  </div>
                  <div className="truncate text-xs text-[hsl(var(--muted-foreground))]">
                    {f.description}
                  </div>
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={f.severity} />
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{f.finding_type}</Badge>
                </TableCell>
                <TableCell>
                  {f.resource_snapshot?.data_tier ? (
                    <DataTierBadge tier={f.resource_snapshot.data_tier} />
                  ) : (
                    <span className="text-xs text-[hsl(var(--muted-foreground))]">—</span>
                  )}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {f.waste_monthly_usd > 0 ? (
                    <span className="font-medium text-[hsl(var(--severity-critical))]">
                      ${f.waste_monthly_usd.toFixed(2)}
                    </span>
                  ) : (
                    <span className="text-xs text-[hsl(var(--muted-foreground))]">—</span>
                  )}
                </TableCell>
                <TableCell className="text-right font-mono text-xs tabular-nums text-[hsl(var(--muted-foreground))]">
                  {f.priority_score}
                </TableCell>
                <TableCell>
                  <Badge variant={statusVariant[status]}>{status}</Badge>
                </TableCell>
                <TableCell>
                  <ChevronRight className="h-4 w-4 text-[hsl(var(--muted-foreground))] transition-transform group-hover:translate-x-0.5 group-hover:text-[hsl(var(--foreground))]" />
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
