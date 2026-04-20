import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import type { FindingResult } from "../../types";

export function SavingsProjection({ findings }: { findings: FindingResult[] }) {
  const totalMonthly = findings
    .filter((f) => f.finding_type === "FINOPS")
    .reduce((sum, f) => sum + f.waste_monthly_usd, 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Savings Projection</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          <div className="flex justify-between">
            <span className="text-sm">Monthly savings</span>
            <span className="font-bold text-emerald-600">${totalMonthly.toFixed(2)}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-sm">Annual projection</span>
            <span className="font-bold text-emerald-600">${(totalMonthly * 12).toFixed(2)}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
