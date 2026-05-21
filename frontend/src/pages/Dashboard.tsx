import { Shield, DollarSign, CheckCircle, Server, Link2, Scan, RefreshCw } from "lucide-react";
import { StatCard } from "../components/common/StatCard";
import { PageHeader } from "../components/common/PageHeader";
import { SeverityChart } from "../components/dashboard/SeverityChart";
import { CostChart } from "../components/dashboard/CostChart";
import { ActivityFeed } from "../components/dashboard/ActivityFeed";
import { FindingTable } from "../components/findings/FindingTable";
import { FindingDetailPanel } from "../components/findings/FindingDetailPanel";
import { EmptyState } from "../components/common/EmptyState";
import { Alert, AlertDescription } from "../components/ui/alert";
import { Button } from "../components/ui/button";
import { DefenderAutoBadge } from "../components/common/DefenderAutoBadge";
import { useFindings } from "../hooks/useFindings";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { triggerScan } from "../api/scans";
import { useRef, useState } from "react";
import type { FindingResult } from "../types";

export function Dashboard() {
  const {
    subscriptions,
    loading: subsLoading,
    selected: selectedSub,
  } = useSubscriptions();
  const { findings, loading, refresh } = useFindings(
    selectedSub?.subscription_id,
  );
  const [selectedFinding, setSelectedFinding] = useState<FindingResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  // Hard-lock against double-fire in addition to the disabled button.
  const scanInFlight = useRef(false);

  const isLoading = loading || subsLoading;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Overview"
          subtitle="Unified security posture and cost governance across your Azure environment."
        />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-32 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]" />
          ))}
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="h-72 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]" />
          <div className="h-72 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]" />
        </div>
      </div>
    );
  }

  const handleRunScan = async () => {
    const subId = selectedSub?.subscription_id;
    if (!subId) return;
    if (scanInFlight.current) return;
    scanInFlight.current = true;
    setScanning(true);
    setScanError(null);
    try {
      await triggerScan({ subscription_id: subId, include_cost: true });
      await refresh();
    } catch (err) {
      const statusCode = (
        err as { response?: { status?: number } }
      )?.response?.status;

      if (statusCode === 429) {
        setScanError(
          "Scan is cooling down for your plan. Free: once every 24 hours, Starter: once per hour, Enterprise: every 15 minutes. Please try again after the cooldown.",
        );
      } else {
        setScanError(err instanceof Error ? err.message : "Scan failed");
      }
    } finally {
      setScanning(false);
      scanInFlight.current = false;
    }
  };

  if (subscriptions.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader title="Overview" subtitle="Connect a subscription to begin scanning." />
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

  if (!selectedSub) {
    return (
      <div className="space-y-6">
        <PageHeader title="Overview" />
        <EmptyState
          icon={<Link2 className="h-12 w-12" />}
          title="No active subscription"
          message="All linked subscriptions are disabled. Re-enable one in Settings to view findings."
          primaryLabel="Go to Settings"
          primaryTo="/settings"
        />
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Overview"
          subtitle={`Active scope: ${selectedSub.display_name}`}
        />
        <EmptyState
          icon={<Scan className="h-12 w-12" />}
          title="No findings yet"
          message={`Run your first scan on ${selectedSub.display_name} to discover security issues, cost waste, and compliance gaps.`}
          primaryLabel={scanning ? "Scanning..." : "Run Your First Scan"}
          primaryOnClick={handleRunScan}
          primaryDisabled={scanning}
          secondary={
            scanError ? (
              <Alert className="mx-auto mt-2 max-w-3xl border-amber-300 bg-amber-50 text-amber-900">
                <AlertDescription className="text-sm font-medium">{scanError}</AlertDescription>
              </Alert>
            ) : null
          }
        />
      </div>
    );
  }

  const critical = findings.filter((f) => f.severity === "CRITICAL").length;
  const high = findings.filter((f) => f.severity === "HIGH").length;
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

  // Lightweight synthetic sparklines until we wire historical telemetry.
  const spark = (seed: number, len = 14) =>
    Array.from({ length: len }, (_, i) => {
      const x = (Math.sin(seed + i * 0.6) + 1) / 2;
      return Math.round(x * 100) / 100;
    });

  const top10 = [...findings]
    .sort((a, b) => b.priority_score - a.priority_score)
    .slice(0, 10);

  return (
    <div className="space-y-8">
      <PageHeader
        title="Overview"
        subtitle={`${selectedSub.display_name} \u00b7 ${findings.length} findings across ${resourceIds.size} resources`}
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={handleRunScan}
            disabled={scanning}
            aria-label="Run scan"
          >
            <RefreshCw className={`h-4 w-4 ${scanning ? "animate-spin" : ""}`} />
            {scanning ? "Scanning..." : "Run scan"}
          </Button>
        }
        meta={<DefenderAutoBadge findings={findings} />}
      />

      {scanError && (
        <Alert className="border-amber-300 bg-amber-50 text-amber-900">
          <AlertDescription className="text-sm font-medium">{scanError}</AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Critical findings"
          value={critical}
          icon={<Shield className="h-4 w-4" />}
          tone="danger"
          hint={critical > 0 ? `${high} high also open` : "No critical issues"}
          delta={critical > 0 ? { value: 12.5, goodDirection: "down" } : undefined}
          sparkline={spark(critical + 1)}
        />
        <StatCard
          label="Wasted spend / mo"
          value={`$${totalWaste.toFixed(2)}`}
          icon={<DollarSign className="h-4 w-4" />}
          tone="warning"
          hint={`$${(totalWaste * 12).toFixed(0)} projected annually`}
          delta={{ value: 4.2, goodDirection: "down" }}
          sparkline={spark(totalWaste + 2)}
        />
        <StatCard
          label="Compliance score"
          value={`${complianceScore}%`}
          icon={<CheckCircle className="h-4 w-4" />}
          tone="success"
          hint={`${complianceFindings} critical/high open`}
          delta={{ value: 2.1, goodDirection: "up" }}
          sparkline={spark(complianceScore + 3)}
        />
        <StatCard
          label="Resources scanned"
          value={resourceIds.size}
          icon={<Server className="h-4 w-4" />}
          tone="brand"
          hint={`${findings.length} total findings`}
          sparkline={spark(resourceIds.size + 4)}
        />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <SeverityChart findings={findings} />
        <CostChart findings={findings} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 overflow-x-auto">
          <FindingTable findings={top10} onSelect={setSelectedFinding} />
        </div>
        <div>
          <ActivityFeed findings={findings} />
        </div>
      </div>

      {selectedFinding && (
        <FindingDetailPanel
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}
