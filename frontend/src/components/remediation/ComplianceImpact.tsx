import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";

export interface ComplianceImpactItem {
  framework: string;
  deltaPercent?: number;
}

export interface ComplianceImpactProps {
  /** Full impact rows: framework + how much compliance improves if fixed. */
  items?: ComplianceImpactItem[];
  /** Fallback: list of framework names (assumes +5% per framework). */
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
        <CardTitle className="text-base">Compliance Impact</CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="divide-y">
          {rows.map((row) => (
            <li
              key={row.framework}
              className="flex items-center justify-between py-2 text-sm"
            >
              <span className="font-medium">{row.framework}</span>
              <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-semibold text-emerald-700">
                +{(row.deltaPercent ?? 0).toFixed(1)}% if fixed
              </span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
