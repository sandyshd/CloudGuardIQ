import { Shield, DollarSign, CheckCircle, Server, Link2, Scan } from "lucide-react";
import { MetricCard } from "../components/dashboard/MetricCard";
import { SeverityChart } from "../components/dashboard/SeverityChart";
import { CostChart } from "../components/dashboard/CostChart";
import { ActivityFeed } from "../components/dashboard/ActivityFeed";
import { FindingTable } from "../components/findings/FindingTable";
import { FindingDetailPanel } from "../components/findings/FindingDetailPanel";
import { EmptyState } from "../components/common/EmptyState";
import { DefenderAutoBadge } from "../components/common/DefenderAutoBadge";
import { useFindings } from "../hooks/useFindings";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { triggerScan } from "../api/scans";
import { useState } from "react";
import type { FindingResult } from "../types";

export function Dashboard() {
  const { findings, loading, refresh } = useFindings();
  const { subscriptions, loading: subsLoading } = useSubscriptions();
  const [selected, setSelected] = useState<FindingResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  const isLoading = loading || subsLoading;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-28 animate-pulse rounded-lg bg-[hsl(var(--muted))]" />
          ))}
        </div>
        <div className="grid gap-4 md:grid-cols-3">
          <div className="h-64 animate-pulse rounded-lg bg-[hsl(var(--muted))]" />
          <div className="h-64 animate-pulse rounded-lg bg-[hsl(var(--muted))]" />
        </div>
      </div>
    );
  }

  const handleRunScan = async () => {
    const subId = subscriptions[0]?.subscription_id;
    if (!subId) return;
    setScanning(true);
    setScanError(null);
    try {
      await triggerScan({ subscription_id: subId, include_cost: true });
      await refresh();
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  if (subscriptions.length === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <EmptyState
          icon={<Link2 className="h-12 w-12" />}
          title="Link a subscription to start scanning"
          message="CloudGuardIQ scans the Azure subscriptions you connect from the Settings page. Once linked, security findings, cost waste, and compliance posture will appear here."
          primaryLabel="Go to Settings"
          primaryTo="/settings"
        />
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <EmptyState
          icon={<Scan className="h-12 w-12" />}
          title="No findings yet"
          message="Run your first scan to discover security issues, cost waste, and compliance gaps across your linked Azure subscriptions."
          primaryLabel={scanning ? "Scanning..." : "Run Your First Scan"}
          primaryOnClick={handleRunScan}
          primaryDisabled={scanning}
          secondary={
            scanError ? (
              <p className="text-sm text-red-600">{scanError}</p>
            ) : null
          }
        />
      </div>
    );
  }

  const critical = findings.filter((f) => f.severity === "CRITICAL").length;
  const totalWaste = findings.reduce((s, f) => s + f.waste_monthly_usd, 0);
  const resourceIds = new Set(
    findings.map((f) => f.resource_snapshot?.id).filter(Boolean)
  );
  const complianceFindings = findings.filter(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH"
  ).length;
  const complianceScore =
    findings.length > 0
      ? Math.round(((findings.length - complianceFindings) / findings.length) * 100)
      : 100;

  const top10 = [...findings]
    .sort((a, b) => b.priority_score - a.priority_score)
    .slice(0, 10);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <DefenderAutoBadge findings={findings} />
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Critical Findings"
          value={critical}
          icon={<Shield className="h-4 w-4 text-red-500" />}
          description={critical > 0 ? "Requires immediate attention" : "No critical issues"}
        />
        <MetricCard
          title="Wasted Spend / mo"
          value={`$${totalWaste.toFixed(2)}`}
          icon={<DollarSign className="h-4 w-4 text-amber-500" />}
          description={`$${(totalWaste * 12).toFixed(0)} projected annually`}
        />
        <MetricCard
          title="Compliance Score"
          value={`${complianceScore}%`}
          icon={<CheckCircle className="h-4 w-4 text-emerald-500" />}
          description={`${complianceFindings} critical/high findings`}
        />
        <MetricCard
          title="Resources Scanned"
          value={resourceIds.size}
          icon={<Server className="h-4 w-4 text-blue-500" />}
          description={`${findings.length} total findings`}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 overflow-x-auto">
          <FindingTable findings={top10} onSelect={setSelected} />
        </div>

        <div className="space-y-4">
          <SeverityChart findings={findings} />
          <CostChart findings={findings} />
          <ActivityFeed findings={findings} />
        </div>
      </div>

      {selected && (
        <FindingDetailPanel
          finding={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}
