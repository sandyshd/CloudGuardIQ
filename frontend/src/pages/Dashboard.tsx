import { Shield, AlertTriangle, DollarSign, TrendingUp } from "lucide-react";
import { MetricCard } from "../components/dashboard/MetricCard";
import { SeverityChart } from "../components/dashboard/SeverityChart";
import { CostChart } from "../components/dashboard/CostChart";
import { ActivityFeed } from "../components/dashboard/ActivityFeed";
import { useFindings } from "../hooks/useFindings";
import { LoadingSpinner } from "../components/common/LoadingSpinner";

export function Dashboard() {
  const { findings, loading } = useFindings();

  if (loading) return <LoadingSpinner />;

  const critical = findings.filter((f) => f.severity === "CRITICAL").length;
  const high = findings.filter((f) => f.severity === "HIGH").length;
  const totalWaste = findings.reduce((s, f) => s + f.waste_monthly_usd, 0);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Total Findings"
          value={findings.length}
          icon={<Shield className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />}
        />
        <MetricCard
          title="Critical"
          value={critical}
          icon={<AlertTriangle className="h-4 w-4 text-red-500" />}
          description={`${high} high severity`}
        />
        <MetricCard
          title="Monthly Waste"
          value={`$${totalWaste.toFixed(2)}`}
          icon={<DollarSign className="h-4 w-4 text-orange-500" />}
        />
        <MetricCard
          title="Annual Savings"
          value={`$${(totalWaste * 12).toFixed(0)}`}
          icon={<TrendingUp className="h-4 w-4 text-emerald-500" />}
          description="Projected if remediated"
        />
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <SeverityChart findings={findings} />
        <CostChart findings={findings} />
      </div>
      <ActivityFeed findings={findings} />
    </div>
  );
}
