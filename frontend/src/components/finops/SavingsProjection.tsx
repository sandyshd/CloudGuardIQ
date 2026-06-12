import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { ArrowDownRight } from "lucide-react";
import type { FindingResult } from "../../types";

function impactOf(f: FindingResult): number {
  const direct = Math.max(f.direct_waste_monthly_usd ?? f.waste_monthly_usd ?? 0, 0);
  const estimated = Math.max(f.estimated_impact_monthly_usd ?? 0, 0);
  return Math.max(direct, estimated, 0);
}

export function SavingsProjection({ findings }: { findings: FindingResult[] }) {
  const totalMonthly = findings
    .filter((f) => f.finding_type === "FINOPS")
    .reduce((sum, f) => sum + impactOf(f), 0);
  const annual = totalMonthly * 12;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Savings projection</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          <div className="rounded-md border border-[hsl(var(--success)/0.3)] bg-[hsl(var(--success)/0.06)] p-4">
            <div className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-[hsl(var(--success))]">
              <ArrowDownRight className="h-3.5 w-3.5" />
              Potential monthly reduction
            </div>
            <div className="mt-1 text-2xl font-semibold tabular-nums text-[hsl(var(--foreground))]">
              ${totalMonthly.toFixed(2)}
            </div>
          </div>
          <dl className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <dt className="text-[hsl(var(--muted-foreground))]">Annualized</dt>
              <dd className="font-semibold tabular-nums text-[hsl(var(--success))]">
                ${annual.toFixed(2)}
              </dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-[hsl(var(--muted-foreground))]">3-year impact</dt>
              <dd className="font-semibold tabular-nums text-[hsl(var(--success))]">
                ${(annual * 3).toFixed(0)}
              </dd>
            </div>
          </dl>
        </div>
      </CardContent>
    </Card>
  );
}
