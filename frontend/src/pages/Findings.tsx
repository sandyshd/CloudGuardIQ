import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useFindings } from "../hooks/useFindings";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { triggerScan } from "../api/scans";
import { FindingTable } from "../components/findings/FindingTable";
import { FindingDetailPanel } from "../components/findings/FindingDetailPanel";
import { Button } from "../components/ui/button";
import { Alert, AlertDescription } from "../components/ui/alert";
import { Scan, Link2 } from "lucide-react";
import type { FindingResult, Severity, FindingType } from "../types";

function formatScanError(err: unknown): string {
  // Surface FastAPI's HTTPException detail (object or string) when present,
  // including the plan-tier scan cooldown payload from /scan.
  const anyErr = err as {
    response?: { status?: number; data?: { detail?: unknown } };
    message?: string;
  };
  const status = anyErr?.response?.status;
  const detail = anyErr?.response?.data?.detail;
  if (status === 429 && detail && typeof detail === "object") {
    const d = detail as Record<string, unknown>;
    const tier = String(d.current_tier ?? "free");
    const cap = Number(d.cap ?? 0);
    const retry = Number(d.retry_after_seconds ?? 0);
    const minutes = Math.ceil(retry / 60);
    const wait =
      retry < 60
        ? `${retry}s`
        : minutes < 60
          ? `${minutes}m`
          : `${Math.ceil(minutes / 60)}h`;
    const last = typeof d.last_event_at === "string" ? d.last_event_at : "";
    const lastSuffix = last ? ` (last scan: ${last})` : "";
    return `Your ${tier} plan allows one scan every ${cap} minute${cap === 1 ? "" : "s"}. Try again in ${wait}${lastSuffix}, or upgrade for more frequent scans.`;
  }
  if (typeof detail === "string") return detail;
  if (err instanceof Error) return err.message;
  return "Scan failed";
}


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
  const scanInFlight = useRef(false);

  const handleRunScan = async () => {
    const subId = effectiveSub ?? selectedSub?.subscription_id;
    if (!subId) {
      navigate("/settings");
      return;
    }
    if (scanInFlight.current) return;
    scanInFlight.current = true;
    setScanning(true);
    setScanError(null);
    try {
      await triggerScan({ subscription_id: subId, include_cost: true });
      await refresh();
    } catch (err) {
      setScanError(formatScanError(err));
    } finally {
      setScanning(false);
      scanInFlight.current = false;
    }
  };

  const filtered = findings.filter((f) => {
    if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
    if (typeFilter !== "ALL" && f.finding_type !== typeFilter) return false;
    return true;
  });

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
        <div className="flex gap-2">
          <Button
            onClick={handleRunScan}
            disabled={scanning || subscriptions.length === 0}
          >
            {scanning ? "Scanning..." : "Run Scan"}
          </Button>
          <Button variant="outline" onClick={refresh}>Refresh</Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {scanError && findings.length > 0 && (
        <Alert variant="destructive">
          <AlertDescription>{scanError}</AlertDescription>
        </Alert>
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

