import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import type { FindingResult } from "../../types";

export function CostChart({ findings }: { findings: FindingResult[] }) {
  const wasteByType: Record<string, number> = {};
  findings
    .filter((f) => f.finding_type === "FINOPS" && f.waste_monthly_usd > 0)
    .forEach((f) => {
      const type = f.resource_snapshot?.resource_type || "Unknown";
      const short = type.split("/").pop() || type;
      wasteByType[short] = (wasteByType[short] || 0) + f.waste_monthly_usd;
    });

  const data = Object.entries(wasteByType)
    .map(([name, waste]) => ({ name, waste: Math.round(waste * 100) / 100 }))
    .sort((a, b) => b.waste - a.waste)
    .slice(0, 8);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Monthly Waste by Resource Type</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" fontSize={12} />
            <YAxis fontSize={12} tickFormatter={(v) => `$${v}`} />
            <Tooltip formatter={(value: number) => [`$${value}`, "Waste"]} />
            <Bar dataKey="waste" fill="hsl(var(--chart-1))" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
