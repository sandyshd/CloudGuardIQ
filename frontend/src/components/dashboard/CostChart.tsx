import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
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
    .map(([name, waste]) => ({ name, waste: Math.round(waste * 100) / 100 }))
    .sort((a, b) => b.waste - a.waste)
    .slice(0, 6);

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">Waste by Category</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20 }}>
            <XAxis type="number" fontSize={12} tickFormatter={(v: number) => `$${v}`} />
            <YAxis type="category" dataKey="name" fontSize={12} width={90} />
            <Tooltip formatter={(value: number) => [`$${value}`, "Waste/mo"]} />
            <Bar dataKey="waste" fill="#f59e0b" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}