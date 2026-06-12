import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../ui/table";
import { SeverityBadge } from "../common/SeverityBadge";
import { cn } from "../../lib/utils";
import type { FindingResult } from "../../types";

function resolveImpact(f: FindingResult): { amount: number; estimated: boolean } {
  const direct = Math.max(f.direct_waste_monthly_usd ?? f.waste_monthly_usd ?? 0, 0);
  const estimated = Math.max(f.estimated_impact_monthly_usd ?? 0, 0);
  const amount = Math.max(direct, estimated, 0);
  return { amount, estimated: amount > 0 && direct <= 0 && estimated > 0 };
}

export function WasteTable({ findings }: { findings: FindingResult[] }) {
  const finops = findings
    .filter((f) => f.finding_type === "FINOPS")
    .sort((a, b) => resolveImpact(b).amount - resolveImpact(a).amount);

  const max = Math.max(resolveImpact(finops[0] ?? ({ waste_monthly_usd: 0 } as FindingResult)).amount, 1);

  if (finops.length === 0) {
    return (
      <div className="px-5 py-12 text-center text-sm text-[hsl(var(--muted-foreground))]">
        No FinOps findings.
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="min-w-[220px]">Rule</TableHead>
          <TableHead className="min-w-[200px]">Resource</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead className="min-w-[200px]">Impact</TableHead>
          <TableHead className="text-right">Waste / mo</TableHead>
          <TableHead className="text-right">Annualized</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {finops.map((f) => {
          const impact = resolveImpact(f);
          const pct = max > 0 ? Math.max(0.04, impact.amount / max) : 0;
          return (
            <TableRow key={f.finding_id}>
              <TableCell className="max-w-[280px]">
                <div className="truncate text-[13px] font-medium text-[hsl(var(--foreground))]">
                  {f.rule_name || f.rule_id}
                </div>
                <div className="truncate text-xs text-[hsl(var(--muted-foreground))]">
                  {f.description}
                </div>
              </TableCell>
              <TableCell className="max-w-[220px]">
                <div className="truncate text-sm font-medium">
                  {f.resource_snapshot?.resource_name || "—"}
                </div>
                <code className="truncate text-[11px] font-mono text-[hsl(var(--muted-foreground))]">
                  {f.resource_snapshot?.resource_type}
                </code>
              </TableCell>
              <TableCell>
                <SeverityBadge severity={f.severity} />
              </TableCell>
              <TableCell className="min-w-[200px]">
                <div className="h-2 w-full overflow-hidden rounded-full bg-[hsl(var(--muted))]">
                  <div
                    className={cn(
                      "h-full rounded-full bg-gradient-to-r from-[hsl(var(--warning))] to-[hsl(var(--severity-critical))] transition-all",
                    )}
                    style={{ width: `${(pct * 100).toFixed(1)}%` }}
                  />
                </div>
              </TableCell>
              <TableCell className="text-right tabular-nums font-medium text-[hsl(var(--severity-critical))]">
                ${impact.amount.toFixed(2)}{impact.estimated ? " *" : ""}
              </TableCell>
              <TableCell className="text-right tabular-nums text-[hsl(var(--muted-foreground))]">
                ${(impact.amount * 12).toFixed(0)}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
