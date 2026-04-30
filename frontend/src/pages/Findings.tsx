import { useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useFindings } from "../hooks/useFindings";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { triggerScan } from "../api/scans";
import { FindingTable } from "../components/findings/FindingTable";
import { FindingDetailPanel } from "../components/findings/FindingDetailPanel";
import { Button } from "../components/ui/button";
import { Alert, AlertDescription } from "../components/ui/alert";
import { Scan, Link2, AlertTriangle, AlertOctagon, Info, ShieldAlert, Activity } from "lucide-react";
import { cn } from "../lib/utils";
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

// Severity tile metadata (order matters -- displayed left-to-right by
// criticality). Colours align with FindingTable badges so the dashboard
// reads consistently.
const SEVERITY_ORDER: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL",
];

const SEVERITY_META: Record<
  Severity,
  { label: string; tone: string; ring: string; icon: typeof AlertOctagon }
> = {
  CRITICAL: {
    label: "Critical",
    tone: "text-red-700 bg-red-50 border-red-200",
    ring: "ring-red-500",
    icon: AlertOctagon,
  },
  HIGH: {
    label: "High",
    tone: "text-orange-700 bg-orange-50 border-orange-200",
    ring: "ring-orange-500",
    icon: AlertTriangle,
  },
  MEDIUM: {
    label: "Medium",
    tone: "text-yellow-700 bg-yellow-50 border-yellow-200",
    ring: "ring-yellow-500",
    icon: ShieldAlert,
  },
  LOW: {
    label: "Low",
    tone: "text-blue-700 bg-blue-50 border-blue-200",
    ring: "ring-blue-500",
    icon: Info,
  },
  INFORMATIONAL: {
    label: "Info",
    tone: "text-slate-700 bg-slate-50 border-slate-200",
    ring: "ring-slate-500",
    icon: Activity,
  },
};

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

  // Severity counts derived from the unfiltered scan result so the tiles
  // always reflect the true distribution, regardless of which severity
  // tile is currently selected. Type filter still narrows the universe so
  // the numbers match what the user sees in the table after toggling
  // SECURITY / FINOPS / COMPLIANCE.
  const severityCounts = useMemo(() => {
    const base: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFORMATIONAL: 0,
    };
    for (const f of findings) {
      if (typeFilter !== "ALL" && f.finding_type !== typeFilter) continue;
      base[f.severity] = (base[f.severity] ?? 0) + 1;
    }
    return base;
  }, [findings, typeFilter]);

  const totalCount = useMemo(
    () =>
      findings.filter(
        (f) => typeFilter === "ALL" || f.finding_type === typeFilter,
      ).length,
    [findings, typeFilter],
  );

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

      {/* Stats header: total + per-severity tiles. Tiles are clickable and
          act as severity quick-filters; clicking the active tile clears
          the filter. */}
      <div className="grid gap-3 grid-cols-2 sm:grid-cols-3 lg:grid-cols-6">
        <button
          type="button"
          onClick={() => setSeverityFilter("ALL")}
          className={cn(
            "flex flex-col items-start rounded-lg border p-4 text-left cursor-pointer transition-shadow hover:shadow-md focus:outline-none focus:ring-2 focus:ring-blue-500",
            severityFilter === "ALL"
              ? "border-blue-500 ring-1 ring-blue-500 shadow-sm bg-[hsl(var(--background))]"
              : "border-[hsl(var(--border))] bg-[hsl(var(--background))]",
          )}
          aria-pressed={severityFilter === "ALL"}
        >
          <span className="text-xs font-medium text-[hsl(var(--muted-foreground))] uppercase tracking-wide">
            Total Findings
          </span>
          <span className="mt-1 text-3xl font-bold">{totalCount}</span>
          <span className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
            {typeFilter === "ALL" ? "All types" : typeFilter}
          </span>
        </button>
        {SEVERITY_ORDER.map((sev) => {
          const meta = SEVERITY_META[sev];
          const Icon = meta.icon;
          const count = severityCounts[sev];
          const active = severityFilter === sev;
          return (
            <button
              key={sev}
              type="button"
              onClick={() => setSeverityFilter(active ? "ALL" : sev)}
              className={cn(
                "flex flex-col items-start rounded-lg border p-4 text-left cursor-pointer transition-shadow hover:shadow-md focus:outline-none focus:ring-2",
                meta.tone,
                active
                  ? cn("ring-1 shadow-sm", meta.ring)
                  : "ring-0",
              )}
              aria-pressed={active}
              title={`Filter by ${meta.label}`}
            >
              <div className="flex w-full items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wide">
                  {meta.label}
                </span>
                <Icon className="h-4 w-4 opacity-70" />
              </div>
              <span className="mt-1 text-3xl font-bold">{count}</span>
              <span className="mt-1 text-xs opacity-70">
                {totalCount > 0
                  ? `${Math.round((count / totalCount) * 100)}% of total`
                  : "—"}
              </span>
            </button>
          );
        })}
      </div>

      <div className="flex flex-wrap items-center gap-2">
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
        {(severityFilter !== "ALL" || typeFilter !== "ALL") && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSeverityFilter("ALL");
              setTypeFilter("ALL");
            }}
          >
            Clear filters
          </Button>
        )}
        <span className="ml-auto text-xs text-[hsl(var(--muted-foreground))]">
          Showing {filtered.length} of {totalCount}
        </span>
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

