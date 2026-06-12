import { useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useFindings } from "../hooks/useFindings";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { triggerScan } from "../api/scans";
import { extractScanLastEventAt, formatScanError, formatScanTimestamp } from "../lib/errors";
import { FindingTable } from "../components/findings/FindingTable";
import { FindingDetailPanel } from "../components/findings/FindingDetailPanel";
import { PageHeader } from "../components/common/PageHeader";
import { EmptyState } from "../components/common/EmptyState";
import { useToast } from "../components/ui/toast";
import { Button } from "../components/ui/button";
import { Alert, AlertDescription } from "../components/ui/alert";
import {
  Scan,
  Link2,
  AlertTriangle,
  AlertOctagon,
  Info,
  ShieldAlert,
  Activity,
  RefreshCw,
  Search,
  X as XIcon,
} from "lucide-react";
import { cn } from "../lib/utils";
import {
  findingSource,
  type FindingSource,
} from "../components/common/SourceBadge";
import type { FindingResult, Severity, FindingType, FindingStatus } from "../types";


const SEVERITY_ORDER: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL",
];

const SEVERITY_META: Record<
  Severity,
  { label: string; tone: string; ringActive: string; icon: typeof AlertOctagon }
> = {
  CRITICAL: {
    label: "Critical",
    tone: "text-[hsl(var(--severity-critical))]",
    ringActive: "ring-[hsl(var(--severity-critical))]",
    icon: AlertOctagon,
  },
  HIGH: {
    label: "High",
    tone: "text-[hsl(var(--severity-high))]",
    ringActive: "ring-[hsl(var(--severity-high))]",
    icon: AlertTriangle,
  },
  MEDIUM: {
    label: "Medium",
    tone: "text-[hsl(var(--severity-medium))]",
    ringActive: "ring-[hsl(var(--severity-medium))]",
    icon: ShieldAlert,
  },
  LOW: {
    label: "Low",
    tone: "text-[hsl(var(--severity-low))]",
    ringActive: "ring-[hsl(var(--severity-low))]",
    icon: Info,
  },
  INFORMATIONAL: {
    label: "Info",
    tone: "text-[hsl(var(--severity-info))]",
    ringActive: "ring-[hsl(var(--severity-info))]",
    icon: Activity,
  },
};

const TYPE_OPTIONS: { id: FindingType | "ALL"; label: string }[] = [
  { id: "ALL", label: "All" },
  { id: "SECURITY", label: "Security" },
  { id: "FINOPS", label: "FinOps" },
  { id: "COMPLIANCE", label: "Compliance" },
];

const SOURCE_OPTIONS: { id: FindingSource | "ALL"; label: string }[] = [
  { id: "ALL", label: "All sources" },
  { id: "AZURE_POLICY", label: "Azure Policy" },
  { id: "NATIVE", label: "CloudGuardIQ" },
];

export function Findings() {
  const [subscriptionFilter, setSubscriptionFilter] = useState<string | "ALL" | "">("");
  const { subscriptions, selected: selectedSub, refresh: refreshSubscriptions } = useSubscriptions();
  const { toast } = useToast();

  const effectiveSub =
    subscriptionFilter === "ALL"
      ? undefined
      : subscriptionFilter !== ""
        ? subscriptionFilter
        : selectedSub?.subscription_id;

  const { findings, loading, error, refresh, applyUpdate, seed } = useFindings(effectiveSub);
  const [lastScanAtOverride, setLastScanAtOverride] = useState<string | null>(null);
  const currentSubscription = effectiveSub
    ? subscriptions.find((s) => s.subscription_id === effectiveSub) ?? null
    : selectedSub;
  const lastScanAt =
    lastScanAtOverride ?? currentSubscription?.last_scan_at ?? null;
  const lastScanLabel = lastScanAt
    ? `Last scan: ${formatScanTimestamp(lastScanAt)}`
    : "Last scan: never";
  const navigate = useNavigate();
  const [selected, setSelected] = useState<FindingResult | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Severity | "ALL">("ALL");
  const [typeFilter, setTypeFilter] = useState<FindingType | "ALL">("ALL");
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "ALL">("ALL");
  const [sourceFilter, setSourceFilter] = useState<FindingSource | "ALL">("ALL");
  const [search, setSearch] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const scanInFlight = useRef(false);

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
      if (statusFilter !== "ALL" && (f.status ?? "OPEN") !== statusFilter) continue;
      base[f.severity] = (base[f.severity] ?? 0) + 1;
    }
    return base;
  }, [findings, typeFilter, statusFilter]);

  const totalCount = useMemo(
    () =>
      findings.filter((f) => {
        if (typeFilter !== "ALL" && f.finding_type !== typeFilter) return false;
        if (statusFilter !== "ALL" && (f.status ?? "OPEN") !== statusFilter) return false;
        return true;
      }).length,
    [findings, typeFilter, statusFilter],
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
      const result = await triggerScan({ subscription_id: subId, include_cost: true });
      // Seed straight from the scan response. Cosmos indexes upserts
      // asynchronously, so an immediate GET /findings (ORDER BY detected_at)
      // can return [] for minutes after a scan, blanking the page until the
      // index catches up. The scan response already holds the full findings
      // array, so render it now; the periodic refresh reconciles later.
      seed(result.findings ?? []);
      setLastScanAtOverride(new Date().toISOString());
      toast({ tone: "success", title: "Scan complete" });
    } catch (err) {
      const msg = formatScanError(err);
      setScanError(msg);
      const fallbackLastScanAt = extractScanLastEventAt(err);
      if (fallbackLastScanAt) setLastScanAtOverride(fallbackLastScanAt);
      toast({ tone: "error", title: "Scan failed", description: msg });
    } finally {
      void refreshSubscriptions();
      setScanning(false);
      scanInFlight.current = false;
    }
  };

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings.filter((f) => {
      if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
      if (typeFilter !== "ALL" && f.finding_type !== typeFilter) return false;
      if (statusFilter !== "ALL" && (f.status ?? "OPEN") !== statusFilter) return false;
      if (sourceFilter !== "ALL" && findingSource(f.rule_id) !== sourceFilter) return false;
      if (q) {
        const blob = [
          f.rule_name,
          f.rule_id,
          f.description,
          f.resource_snapshot?.resource_name,
          f.resource_snapshot?.resource_type,
          f.resource_snapshot?.id,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!blob.includes(q)) return false;
      }
      return true;
    });
  }, [findings, severityFilter, typeFilter, statusFilter, sourceFilter, search]);

  const hasActiveFilters =
    severityFilter !== "ALL" ||
    typeFilter !== "ALL" ||
    statusFilter !== "ALL" ||
    sourceFilter !== "ALL" ||
    search.length > 0;

  if (loading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Findings" subtitle="Loading findings..." />
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          {[...Array(6)].map((_, i) => (
            <div
              key={i}
              className="h-24 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]"
            />
          ))}
        </div>
        <div className="space-y-2">
          {[...Array(8)].map((_, i) => (
            <div
              key={i}
              className="h-12 animate-pulse rounded bg-[hsl(var(--muted))]"
            />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Findings"
        subtitle="Security, FinOps, and compliance issues detected across your scoped subscriptions."
        actions={
          <div className="flex flex-col items-end gap-1">
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => refresh()} aria-label="Refresh">
                <RefreshCw className="h-4 w-4" />
                Refresh
              </Button>
              <Button
                size="sm"
                onClick={handleRunScan}
                disabled={scanning || subscriptions.length === 0}
              >
                <Scan className={cn("h-4 w-4", scanning && "animate-pulse")} />
                {scanning ? "Scanning..." : "Run scan"}
              </Button>
            </div>
            <span className="text-xs text-[hsl(var(--muted-foreground))]">{lastScanLabel}</span>
          </div>
        }
      />

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {scanError && findings.length > 0 && (
        <Alert variant="warning">
          <AlertDescription>{scanError}</AlertDescription>
        </Alert>
      )}

      {/* Severity tile row (clickable filters) */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <button
          type="button"
          onClick={() => setSeverityFilter("ALL")}
          className={cn(
            "group flex flex-col items-start gap-1 rounded-[var(--radius)] border bg-[hsl(var(--card))] p-4 text-left shadow-sm transition-all hover:shadow-md focus-visible:outline-none focus-visible:ring-2",
            severityFilter === "ALL"
              ? "border-[hsl(var(--primary))] ring-1 ring-[hsl(var(--primary))]"
              : "border-[hsl(var(--border))]",
          )}
          aria-pressed={severityFilter === "ALL"}
        >
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
            Total
          </span>
          <span className="text-2xl font-semibold tracking-tight tabular-nums text-[hsl(var(--foreground))]">
            {totalCount}
          </span>
          <span className="text-[11px] text-[hsl(var(--muted-foreground))]">
            {typeFilter === "ALL" ? "All types" : TYPE_OPTIONS.find((o) => o.id === typeFilter)?.label}
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
                "group flex flex-col items-start gap-1 rounded-[var(--radius)] border bg-[hsl(var(--card))] p-4 text-left shadow-sm transition-all hover:shadow-md focus-visible:outline-none focus-visible:ring-2",
                active
                  ? cn("ring-1", meta.ringActive, "border-transparent")
                  : "border-[hsl(var(--border))]",
              )}
              aria-pressed={active}
              title={`Filter by ${meta.label}`}
            >
              <div className="flex w-full items-center justify-between">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                  {meta.label}
                </span>
                <Icon className={cn("h-4 w-4", meta.tone)} />
              </div>
              <span className={cn("text-2xl font-semibold tracking-tight tabular-nums", meta.tone)}>
                {count}
              </span>
              <span className="text-[11px] text-[hsl(var(--muted-foreground))]">
                {totalCount > 0
                  ? `${Math.round((count / totalCount) * 100)}% of total`
                  : "ΓÇö"}
              </span>
            </button>
          );
        })}
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-2 shadow-sm">
        {/* Search */}
        <div className="relative min-w-[240px] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
          <input
            type="search"
            placeholder="Search resource, rule, description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-9 w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] pl-8 pr-3 text-sm focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
          />
        </div>

        {/* Type segmented */}
        <div className="inline-flex rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] p-0.5">
          {TYPE_OPTIONS.map((opt) => (
            <button
              key={opt.id}
              type="button"
              onClick={() => setTypeFilter(opt.id)}
              className={cn(
                "px-3 py-1.5 text-xs font-medium transition-colors rounded",
                typeFilter === opt.id
                  ? "bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] shadow-sm"
                  : "text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]",
              )}
            >
              {opt.label}
            </button>
          ))}
        </div>

        <select
          aria-label="Status"
          className="h-9 rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-2 text-sm focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as FindingStatus | "ALL")}
        >
          <option value="ALL">All statuses</option>
          <option value="OPEN">Open</option>
          <option value="RESOLVED">Resolved</option>
          <option value="SNOOZED">Snoozed</option>
          <option value="APPLIED">Applied</option>
        </select>

        <select
          aria-label="Source"
          className="h-9 rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-2 text-sm focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
          value={sourceFilter}
          onChange={(e) => setSourceFilter(e.target.value as FindingSource | "ALL")}
        >
          {SOURCE_OPTIONS.map((opt) => (
            <option key={opt.id} value={opt.id}>
              {opt.label}
            </option>
          ))}
        </select>

        <select
          aria-label="Subscription"
          className="h-9 max-w-[200px] truncate rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-2 text-sm focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
          value={subscriptionFilter}
          onChange={(e) => setSubscriptionFilter(e.target.value)}
        >
          <option value="">Active subscription</option>
          <option value="ALL">All subscriptions</option>
          {subscriptions.map((sub) => (
            <option key={sub.subscription_id} value={sub.subscription_id}>
              {sub.display_name || sub.subscription_id}
            </option>
          ))}
        </select>

        {hasActiveFilters && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSeverityFilter("ALL");
              setTypeFilter("ALL");
              setStatusFilter("ALL");
              setSourceFilter("ALL");
              setSearch("");
            }}
          >
            <XIcon className="h-3.5 w-3.5" />
            Clear
          </Button>
        )}

        <span className="ml-auto pr-2 text-xs text-[hsl(var(--muted-foreground))]">
          {filtered.length} of {totalCount}
        </span>
      </div>

      {filtered.length === 0 && findings.length > 0 && statusFilter !== "ALL" && (
        <Alert>
          <AlertDescription className="flex items-center justify-between gap-3">
            <span>
              {findings.length} finding{findings.length === 1 ? "" : "s"} hidden by the
              "{statusFilter}" status filter.
            </span>
            <Button size="sm" variant="outline" onClick={() => setStatusFilter("ALL")}>
              Show all statuses
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {findings.length === 0 && !error ? (
        subscriptions.length === 0 ? (
          <EmptyState
            icon={<Link2 className="h-7 w-7" />}
            title="Link a subscription to start scanning"
            message="Connect an Azure subscription on the Settings page before running your first scan."
            primaryLabel="Go to Settings"
            primaryTo="/settings"
          />
        ) : (
          <EmptyState
            icon={<Scan className="h-7 w-7" />}
            title="No findings yet"
            message="Run your first scan to discover security issues and cost waste."
            primaryLabel={scanning ? "Scanning..." : "Run your first scan"}
            primaryOnClick={handleRunScan}
            primaryDisabled={scanning}
            secondary={
              scanError ? (
                <p className="text-sm text-[hsl(var(--severity-critical))]">{scanError}</p>
              ) : null
            }
          />
        )
      ) : (
        <FindingTable findings={filtered} onSelect={setSelected} />
      )}

      {selected && (
        <FindingDetailPanel
          finding={selected}
          onClose={() => setSelected(null)}
          onUpdate={(next) => {
            applyUpdate(next);
            setSelected(next);
          }}
        />
      )}
    </div>
  );
}










