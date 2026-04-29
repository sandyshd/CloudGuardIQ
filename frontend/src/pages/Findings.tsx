import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useFindings } from "../hooks/useFindings";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { triggerScan } from "../api/scans";
import { FindingTable } from "../components/findings/FindingTable";
import { FindingDetailPanel } from "../components/findings/FindingDetailPanel";
import { Button } from "../components/ui/button";
import { Alert, AlertDescription } from "../components/ui/alert";
import { Info, Scan, Link2 } from "lucide-react";
import type { FindingResult, Severity, FindingType } from "../types";

export function Findings() {
  // Page-local "All / specific" filter. Defaults to undefined which means
  // "use the globally selected subscription". Selecting "ALL" or a
  // specific id from the page-local dropdown overrides the global pick
  // for this view only.
  const [subscriptionFilter, setSubscriptionFilter] = useState<string | "ALL" | "">("");
  const { subscriptions, selected: selectedSub } = useSubscriptions();

  const effectiveSub =
    subscriptionFilter === "ALL"
      ? undefined
      : subscriptionFilter !== ""
        ? subscriptionFilter
        : selectedSub?.subscription_id;

  const { findings, loading, error, refresh } = useFindings(effectiveSub);
  const navigate = useNavigate();
  const [selected, setSelected] = useState<FindingResult | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Severity | "ALL">("ALL");
  const [typeFilter, setTypeFilter] = useState<FindingType | "ALL">("ALL");
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  const handleRunScan = async () => {
    const subId = effectiveSub ?? selectedSub?.subscription_id;
    if (!subId) {
      navigate("/settings");
      return;
    }
    setScanning(true);
    setScanError(null);
    try {
      await triggerScan({ subscription_id: subId, include_cost: true });
      await refresh();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Scan failed";
      setScanError(msg);
    } finally {
      setScanning(false);
    }
  };

  const filtered = findings.filter((f) => {
    if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
    if (typeFilter !== "ALL" && f.finding_type !== typeFilter) return false;
    return true;
  });

  const allTier1 =
    findings.length > 0 &&
    findings.every(
      (f) => f.resource_snapshot?.data_tier === "TIER1_NATIVE"
    );

  if (loading) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold">Findings</h1>
        <div className="space-y-3">
          {[...Array(6)].map((_, i) => (
            <div
              key={i}
              className="h-12 animate-pulse rounded bg-[hsl(var(--muted))]"
            />
          ))}
        </div>
      </div>
    );
  }

  // The dropdown shows "Active subscription" by default (mirrors header
  // selector), plus an explicit "All Subscriptions" option, plus each sub.
  const dropdownValue = subscriptionFilter;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Findings</h1>
        <Button onClick={refresh}>Refresh</Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {allTier1 && (
        <div className="flex items-start gap-3 rounded-lg border border-blue-200 bg-blue-50 p-4">
          <Info className="h-5 w-5 text-blue-500 mt-0.5 shrink-0" />
          <div className="text-sm text-blue-800">
            <p>
              Enable Defender for Cloud free CSPM to enrich these findings with
              security scores. Takes 5 minutes, at no cost.
            </p>
            <a
              href="https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-enhanced-security"
              target="_blank"
              rel="noopener noreferrer"
              className="mt-1 inline-flex items-center gap-1 font-medium text-blue-600 hover:underline"
            >
              Enable Defender &rarr;
            </a>
          </div>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <select
          className="rounded border px-3 py-2 text-sm bg-[hsl(var(--background))]"
          value={severityFilter}
          onChange={(e) =>
            setSeverityFilter(e.target.value as Severity | "ALL")
          }
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFORMATIONAL">Informational</option>
        </select>
        <select
          className="rounded border px-3 py-2 text-sm bg-[hsl(var(--background))]"
          value={typeFilter}
          onChange={(e) =>
            setTypeFilter(e.target.value as FindingType | "ALL")
          }
        >
          <option value="ALL">All Types</option>
          <option value="SECURITY">Security</option>
          <option value="FINOPS">FinOps</option>
          <option value="COMPLIANCE">Compliance</option>
        </select>
        <select
          className="rounded border px-3 py-2 text-sm bg-[hsl(var(--background))]"
          value={dropdownValue}
          onChange={(e) => setSubscriptionFilter(e.target.value)}
        >
          <option value="">Active subscription</option>
          <option value="ALL">All Subscriptions</option>
          {subscriptions.map((sub) => (
            <option key={sub.subscription_id} value={sub.subscription_id}>
              {sub.display_name || sub.subscription_id}
            </option>
          ))}
        </select>
      </div>

      {findings.length === 0 && !error ? (
        subscriptions.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-12 text-center">
            <Link2 className="h-12 w-12 text-[hsl(var(--muted-foreground))] mb-4" />
            <h2 className="text-lg font-semibold">
              Link a subscription to start scanning
            </h2>
            <p className="mt-1 mb-4 max-w-md text-sm text-[hsl(var(--muted-foreground))]">
              Connect an Azure subscription on the Settings page before running
              your first scan.
            </p>
            <Button onClick={() => navigate("/settings")}>Go to Settings</Button>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-12 text-center">
            <Scan className="h-12 w-12 text-[hsl(var(--muted-foreground))] mb-4" />
            <h2 className="text-lg font-semibold">No findings yet</h2>
            <p className="text-sm text-[hsl(var(--muted-foreground))] mt-1 mb-4">
              Run your first scan to discover security issues and cost waste.
            </p>
            {scanError && (
              <p className="mb-2 text-sm text-red-600">{scanError}</p>
            )}
            <Button onClick={handleRunScan} disabled={scanning}>
              {scanning ? "Scanning..." : "Run Your First Scan"}
            </Button>
          </div>
        )
      ) : (
        <FindingTable findings={filtered} onSelect={setSelected} />
      )}

      {selected && (
        <FindingDetailPanel
          finding={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}
