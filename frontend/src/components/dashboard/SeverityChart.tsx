import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import type { FindingResult } from "../../types";

const COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#3b82f6",
  INFORMATIONAL: "#9ca3af",
};

export function SeverityChart({ findings }: { findings: FindingResult[] }) {
  const counts: Record<string, number> = {};
  findings.forEach((f) => {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  });

  const data = Object.entries(counts).map(([name, value]) => ({ name, value }));

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Findings by Severity</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={250}>
          <PieChart>
            <Pie data={data} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={5} dataKey="value">
              {data.map((entry) => (
                <Cell key={entry.name} fill={COLORS[entry.name] || "#6b7280"} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
