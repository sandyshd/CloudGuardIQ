import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import type { FindingResult } from "../../types";

export function FrameworkScorecard({ findings }: { findings: FindingResult[] }) {
  const frameworks: Record<string, { total: number; passed: number }> = {};

  findings.forEach((f) => {
    f.compliance_frameworks.forEach((fw) => {
      if (!frameworks[fw]) frameworks[fw] = { total: 0, passed: 0 };
      frameworks[fw].total++;
    });
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Framework Scorecard</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {Object.entries(frameworks).map(([name, { total }]) => (
            <div key={name} className="flex items-center justify-between">
              <span className="text-sm font-medium">{name}</span>
              <span className="text-sm text-[hsl(var(--muted-foreground))]">{total} findings</span>
            </div>
          ))}
          {Object.keys(frameworks).length === 0 && (
            <p className="text-sm text-[hsl(var(--muted-foreground))]">No compliance data</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
