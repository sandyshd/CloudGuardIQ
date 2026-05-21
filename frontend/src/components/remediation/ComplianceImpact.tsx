import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { ShieldCheck } from "lucide-react";

export interface ComplianceImpactItem {
  framework: string;
  deltaPercent?: number;
}

export interface ComplianceImpactProps {
  items?: ComplianceImpactItem[];
  frameworks?: string[];
}

export function ComplianceImpact({
  items,
  frameworks,
}: ComplianceImpactProps) {
  const rows: ComplianceImpactItem[] =
    items ??
    (frameworks ?? []).map((framework) => ({
      framework,
      deltaPercent: 5,
    }));

  if (rows.length === 0) return null;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-[hsl(var(--success))]" />
          <CardTitle>Compliance impact</CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        <ul className="divide-y divide-[hsl(var(--border))]">
          {rows.map((row) => (
            <li
              key={row.framework}
              className="flex items-center justify-between py-2.5 text-sm"
            >
              <span className="font-medium text-[hsl(var(--foreground))]">
                {row.framework}
              </span>
              <span className="rounded-md bg-[hsl(var(--success)/0.14)] px-2 py-0.5 text-[11px] font-semibold text-[hsl(var(--success))]">
                +{(row.deltaPercent ?? 0).toFixed(1)}% if fixed
              </span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
