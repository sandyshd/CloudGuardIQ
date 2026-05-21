import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import type { FindingResult } from "../../types";

const CATEGORY_MAP: Record<string, string> = {
  virtualMachines: "Idle VMs",
  storageAccounts: "Storage",
  disks: "Disks",
  publicIPAddresses: "Public IPs",
  loadBalancers: "Load Balancers",
  networkInterfaces: "NICs",
  snapshots: "Snapshots",
};

function chartColor(idx: number): string {
  return `hsl(var(--chart-${(idx % 6) + 1}))`;
}

function categorize(resourceType: string): string {
  const short = resourceType.split("/").pop() || resourceType;
  return CATEGORY_MAP[short] || short;
}

export function CostChart({ findings }: { findings: FindingResult[] }) {
  const wasteByCategory: Record<string, number> = {};
  findings
    .filter((f) => f.waste_monthly_usd > 0)
    .forEach((f) => {
      const category = f.resource_snapshot
        ? categorize(f.resource_snapshot.resource_type)
        : "Other";
      wasteByCategory[category] =
        (wasteByCategory[category] || 0) + f.waste_monthly_usd;
    });

  const data = Object.entries(wasteByCategory)
    .map(([name, waste]) => ({ name, value: Math.round(waste * 100) / 100 }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 6);

  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Waste by category</CardTitle>
      </CardHeader>
      <CardContent>
        {total === 0 ? (
          <div className="flex h-[260px] items-center justify-center text-sm text-[hsl(var(--muted-foreground))]">
            No tracked waste
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="name"
                innerRadius={58}
                outerRadius={92}
                paddingAngle={2}
                stroke="hsl(var(--card))"
                strokeWidth={2}
              >
                {data.map((entry, idx) => (
                  <Cell key={entry.name} fill={chartColor(idx)} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: 8,
                  fontSize: 12,
                  color: "hsl(var(--foreground))",
                }}
                formatter={(value: number, _name, ctx) => {
                  const pct = total > 0 ? Math.round((value / total) * 100) : 0;
                  return [`$${value} (${pct}%)`, ctx.payload.name];
                }}
              />
              <Legend
                verticalAlign="bottom"
                height={32}
                iconType="circle"
                wrapperStyle={{ fontSize: 12, color: "hsl(var(--muted-foreground))" }}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
