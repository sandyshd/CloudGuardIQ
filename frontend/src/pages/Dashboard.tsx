import { useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  AlertTriangle,
  DollarSign,
  Sparkles,
  ArrowRight,
  ArrowUpRight,
  ArrowDownRight,
  RefreshCw,
  Scan,
  ShieldCheck,
  CircleDot,
  CircleSlash,
  Activity,
  Wrench,
  Plug,
} from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { EmptyState } from "../components/common/EmptyState";
import { SeverityBadge } from "../components/common/SeverityBadge";
import { Alert, AlertDescription } from "../components/ui/alert";
import { Button } from "../components/ui/button";
import { useToast } from "../components/ui/toast";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import {
  FindingsOverTimeChart,
  CostByServiceChart,
  Sparkline,
  ProgressRing,
} from "../components/dashboard/OverviewCharts";
import { FindingDetailPanel } from "../components/findings/FindingDetailPanel";
import { useFindings } from "../hooks/useFindings";
import { useComplianceScorecard } from "../hooks/useComplianceScorecard";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { triggerScan } from "../api/scans";
import { TIER2_VALUES, TIER3_VALUES } from "../types";
import type { FindingResult, Severity, DataTier } from "../types";
import { cn } from "../lib/utils";

const SEV_WEIGHT: Record<Severity, number> = {
  CRITICAL: 10,
  HIGH: 5,
  MEDIUM: 2,
  LOW: 0.5,
  INFORMATIONAL: 0,
};

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "hsl(var(--severity-critical))",
  HIGH: "hsl(var(--severity-high))",
  MEDIUM: "hsl(var(--severity-medium))",
  LOW: "hsl(var(--severity-low))",
  INFORMATIONAL: "hsl(var(--severity-info))",
};


function postureScore(findings: FindingResult[]): number {
  const open = findings.filter((f) => (f.status ?? "OPEN") === "OPEN");
  const penalty = open.reduce((s, f) => s + (SEV_WEIGHT[f.severity] ?? 0), 0);
  return Math.max(0, Math.min(100, Math.round(100 - penalty)));
}

function postureSparkline(findings: FindingResult[], days = 30): number[] {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const points: number[] = [];
  const buckets = 12;
  const step = days / buckets;
  for (let i = buckets - 1; i >= 0; i--) {
    const cutoff = new Date(today);
    cutoff.setDate(cutoff.getDate() - Math.round(i * step));
    const detected = findings.filter(
      (f) => new Date(f.detected_at) <= cutoff,
    );
    points.push(postureScore(detected));
  }
  return points;
}

function fmtMoney(n: number): string {
  if (n >= 10000) return `$${(n / 1000).toFixed(1)}k`;
  if (n >= 100) return `$${n.toFixed(0)}`;
  return `$${n.toFixed(2)}`;
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d ago`;
  return new Date(iso).toLocaleDateString();
}

export function Dashboard() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { subscriptions, loading: subsLoading, selected: selectedSub } =
    useSubscriptions();
  const { findings, loading, refresh } = useFindings(selectedSub?.subscription_id);
  const { scorecard, loading: scorecardLoading } = useComplianceScorecard(selectedSub?.subscription_id);
  const [selectedFinding, setSelectedFinding] = useState<FindingResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const scanInFlight = useRef(false);

  const isLoading = loading || subsLoading;

  const handleRunScan = async () => {
    const subId = selectedSub?.subscription_id;
    if (!subId || scanInFlight.current) return;
    scanInFlight.current = true;
    setScanning(true);
    setScanError(null);
    try {
      await triggerScan({ subscription_id: subId, include_cost: true });
      await refresh();
      toast({ title: "Scan complete", description: "Findings refreshed." });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Scan failed";
      setScanError(msg);
      toast({ title: "Scan failed", description: msg, tone: "error" });
    } finally {
      scanInFlight.current = false;
      setScanning(false);
    }
  };

  // ── Derived metrics ────────────────────────────────────────────────────
  const metrics = useMemo(() => {
    const open = findings.filter((f) => (f.status ?? "OPEN") === "OPEN");
    const score = postureScore(findings);
    const spark = postureSparkline(findings);
    const trend = spark.length >= 2 ? spark[spark.length - 1] - spark[0] : 0;

    const sevCounts: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFORMATIONAL: 0,
    };
    open.forEach((f) => (sevCounts[f.severity] += 1));

    // Resources de-duped from finding snapshots.
    const resourceById = new Map<string, NonNullable<FindingResult["resource_snapshot"]>>();
    findings.forEach((f) => {
      if (f.resource_snapshot) resourceById.set(f.resource_snapshot.id, f.resource_snapshot);
    });
    const resources = Array.from(resourceById.values());
    const monthlySpend = resources.reduce((s, r) => s + (r.cost_monthly ?? 0), 0);

    // MTD vs forecast: assume cost_monthly is full-month projection.
    const now = new Date();
    const dayOfMonth = now.getDate();
    const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
    const mtd = monthlySpend * (dayOfMonth / daysInMonth);
    const forecast = monthlySpend;

    // Savings from FINOPS findings.
    const finops = findings.filter((f) => f.finding_type === "FINOPS");
    const savings = finops.reduce((s, f) => s + (f.waste_monthly_usd ?? 0), 0);

    // Cost by service (top 8).
    const byService = new Map<string, number>();
    resources.forEach((r) => {
      const k = (r.resource_type || "Other").split("/").pop() || "Other";
      byService.set(k, (byService.get(k) ?? 0) + (r.cost_monthly ?? 0));
    });
    const costByService = Array.from(byService.entries())
      .map(([service, cost]) => ({ service, cost }))
      .filter((d) => d.cost > 0)
      .sort((a, b) => b.cost - a.cost)
      .slice(0, 8);

    // Top risks: highest priority_score, grouped by rule for "affected resources" count.
    const byRule = new Map<string, { rule: FindingResult; resources: Set<string> }>();
    open.forEach((f) => {
      const k = f.rule_id;
      const existing = byRule.get(k);
      const rid = f.resource_snapshot?.id ?? f.finding_id;
      if (existing) {
        existing.resources.add(rid);
        if ((f.priority_score ?? 0) > (existing.rule.priority_score ?? 0)) {
          existing.rule = f;
        }
      } else {
        byRule.set(k, { rule: f, resources: new Set([rid]) });
      }
    });
    const topRisks = Array.from(byRule.values())
      .sort(
        (a, b) =>
          (b.rule.priority_score ?? 0) - (a.rule.priority_score ?? 0) ||
          (SEV_WEIGHT[b.rule.severity] ?? 0) - (SEV_WEIGHT[a.rule.severity] ?? 0),
      )
      .slice(0, 5);


    // Data tier presence.
    const tiers = new Set<DataTier>();
    resources.forEach((r) => tiers.add(r.data_tier));
    const tier2Active = TIER2_VALUES.some((t) => tiers.has(t));
    const tier3Active = TIER3_VALUES.some((t) => tiers.has(t));

    // Recent activity = most recent findings as a timeline (proxy for scan/remediation events).
    const recent = [...findings]
      .sort((a, b) => new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime())
      .slice(0, 8);

    return {
      open,
      score,
      spark,
      trend,
      sevCounts,
      resourcesCount: resources.length,
      monthlySpend,
      mtd,
      forecast,
      savings,
      finopsCount: finops.length,
      costByService,
      topRisks,
      tier2Active,
      tier3Active,
      recent,
    };
  }, [findings]);

  // ── Render ─────────────────────────────────────────────────────────────
  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Overview" subtitle="Unified security posture and cost governance." />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-36 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]"
            />
          ))}
        </div>
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2 h-72 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]" />
          <div className="h-72 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]" />
        </div>
      </div>
    );
  }

  if (subscriptions.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader title="Overview" />
        <EmptyState
          icon={<Plug className="h-7 w-7" />}
          title="No subscriptions connected"
          message="Connect an Azure subscription to start scanning for security and cost findings."
          primaryLabel="Connect subscription" primaryTo="/onboarding"
        />
      </div>
    );
  }

  const scoreColor =
    metrics.score >= 80
      ? "hsl(var(--success))"
      : metrics.score >= 60
        ? "hsl(var(--severity-medium))"
        : "hsl(var(--severity-critical))";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Overview"
        subtitle={`${selectedSub?.subscription_id ?? "—"} · ${findings.length} findings across ${metrics.resourcesCount} resources`}
        actions={
          <Button onClick={handleRunScan} disabled={scanning} variant="outline" size="sm">
            {scanning ? (
              <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Scan className="mr-2 h-4 w-4" />
            )}
            {scanning ? "Scanning…" : "Run scan"}
          </Button>
        }
      />

      {scanError && (
        <Alert variant="destructive">
          <AlertDescription>{scanError}</AlertDescription>
        </Alert>
      )}

      {/* ── Hero KPI row ─────────────────────────────────────────────── */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {/* 1. Security Posture Score */}
        <Card>
          <CardContent className="p-5">
            <div className="flex items-start justify-between">
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                  Security Posture
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span
                    className="text-4xl font-semibold leading-none"
                    style={{ color: scoreColor }}
                  >
                    {metrics.score}
                  </span>
                  <span className="text-sm text-[hsl(var(--muted-foreground))]">/ 100</span>
                </div>
                <div className="mt-2 flex items-center gap-1.5 text-xs">
                  {metrics.trend >= 0 ? (
                    <ArrowUpRight className="h-3.5 w-3.5 text-[hsl(var(--success))]" />
                  ) : (
                    <ArrowDownRight className="h-3.5 w-3.5 text-[hsl(var(--severity-critical))]" />
                  )}
                  <span
                    className={cn(
                      "font-medium",
                      metrics.trend >= 0
                        ? "text-[hsl(var(--success))]"
                        : "text-[hsl(var(--severity-critical))]",
                    )}
                  >
                    {metrics.trend >= 0 ? "+" : ""}
                    {metrics.trend.toFixed(0)}
                  </span>
                  <span className="text-[hsl(var(--muted-foreground))]">last 30d</span>
                </div>
              </div>
              <Shield className="h-5 w-5 text-[hsl(var(--muted-foreground))]" />
            </div>
            <div className="mt-3">
              <Sparkline values={metrics.spark} color={scoreColor} width={220} height={36} />
            </div>
          </CardContent>
        </Card>

        {/* 2. Open Findings */}
        <Card>
          <CardContent className="p-5">
            <div className="flex items-start justify-between">
              <div className="min-w-0">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                  Open Findings
                </div>
                <div className="mt-2 text-4xl font-semibold leading-none text-[hsl(var(--foreground))]">
                  {metrics.open.length}
                </div>
              </div>
              <AlertTriangle className="h-5 w-5 text-[hsl(var(--muted-foreground))]" />
            </div>
            <div className="mt-4 flex flex-wrap gap-1.5">
              {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[]).map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => navigate(`/findings?severity=${s}`)}
                  className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset ring-[hsl(var(--border))] transition-colors hover:bg-[hsl(var(--accent)/0.1)]"
                  style={{
                    background: `${SEV_COLOR[s]}1a`,
                    color: SEV_COLOR[s],
                  }}
                >
                  <span
                    className="h-1.5 w-1.5 rounded-full"
                    style={{ background: SEV_COLOR[s] }}
                  />
                  {metrics.sevCounts[s]} {s[0]}{s.slice(1).toLowerCase()}
                </button>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* 3. Monthly Cloud Spend */}
        <Card>
          <CardContent className="p-5">
            <div className="flex items-start justify-between">
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                  Monthly Cloud Spend
                </div>
                <div className="mt-2 text-4xl font-semibold leading-none text-[hsl(var(--foreground))]">
                  {fmtMoney(metrics.mtd)}
                </div>
                <div className="mt-2 text-xs text-[hsl(var(--muted-foreground))]">
                  Forecast {fmtMoney(metrics.forecast)} / mo
                </div>
              </div>
              <DollarSign className="h-5 w-5 text-[hsl(var(--muted-foreground))]" />
            </div>
            <div className="mt-3">
              <Sparkline
                values={
                  metrics.forecast > 0
                    ? Array.from({ length: 12 }, (_, i) =>
                        (metrics.forecast * (i + 1)) / 12,
                      )
                    : [0, 0]
                }
                color="hsl(var(--primary))"
                width={220}
                height={36}
              />
            </div>
          </CardContent>
        </Card>

        {/* 4. Identified Savings */}
        <Card>
          <CardContent className="p-5">
            <div className="flex items-start justify-between">
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                  Identified Savings
                </div>
                <div className="mt-2 text-4xl font-semibold leading-none text-[hsl(var(--success))]">
                  {fmtMoney(metrics.savings)}
                </div>
                <div className="mt-2 text-xs text-[hsl(var(--muted-foreground))]">
                  {metrics.finopsCount} recommendation
                  {metrics.finopsCount === 1 ? "" : "s"} / mo
                </div>
              </div>
              <Sparkles className="h-5 w-5 text-[hsl(var(--muted-foreground))]" />
            </div>
            <Button
              variant="outline"
              size="sm"
              className="mt-3 w-full"
              onClick={() => navigate("/finops/optimization")}
              disabled={metrics.finopsCount === 0}
            >
              Apply all
              <ArrowRight className="ml-2 h-3.5 w-3.5" />
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* ── Below KPIs: Findings over time (2/3) + Top risks (1/3) ───── */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Findings over time</CardTitle>
            <span className="text-xs text-[hsl(var(--muted-foreground))]">Last 30 days</span>
          </CardHeader>
          <CardContent>
            <FindingsOverTimeChart findings={findings} days={30} />
            <div className="mt-2 flex flex-wrap gap-3 text-[11px]">
              {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[]).map((s) => (
                <span key={s} className="inline-flex items-center gap-1.5">
                  <span
                    className="h-2 w-2 rounded-full"
                    style={{ background: SEV_COLOR[s] }}
                  />
                  <span className="text-[hsl(var(--muted-foreground))]">
                    {s[0]}
                    {s.slice(1).toLowerCase()}
                  </span>
                </span>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top risks</CardTitle>
          </CardHeader>
          <CardContent>
            {metrics.topRisks.length === 0 ? (
              <p className="py-8 text-center text-sm text-[hsl(var(--muted-foreground))]">
                No open risks.
              </p>
            ) : (
              <ul className="space-y-3">
                {metrics.topRisks.map(({ rule, resources }) => (
                  <li
                    key={rule.rule_id}
                    className="flex items-start gap-3 border-b border-[hsl(var(--border))] pb-3 last:border-b-0 last:pb-0"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={rule.severity} />
                        <span className="text-[11px] text-[hsl(var(--muted-foreground))]">
                          {resources.size} resource{resources.size === 1 ? "" : "s"}
                        </span>
                      </div>
                      <div className="mt-1 truncate text-sm font-medium text-[hsl(var(--foreground))]">
                        {rule.rule_name || rule.rule_id}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setSelectedFinding(rule)}
                      className="inline-flex shrink-0 items-center gap-1 text-xs font-medium text-[hsl(var(--primary))] hover:underline"
                    >
                      Investigate
                      <ArrowRight className="h-3 w-3" />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Second row: Cost by service + Compliance scorecard ───────── */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Cost by service</CardTitle>
            <button
              type="button"
              onClick={() => navigate("/finops")}
              className="text-xs font-medium text-[hsl(var(--primary))] hover:underline"
            >
              Cost Explorer →
            </button>
          </CardHeader>
          <CardContent>
            <CostByServiceChart
              data={metrics.costByService}
              onSelect={() => navigate("/finops")}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Compliance</CardTitle>
          </CardHeader>
          <CardContent>
            {scorecardLoading ? (
              <div className="grid grid-cols-2 gap-4">
                {Array.from({ length: 4 }).map((_, i) => (
                  <div
                    key={i}
                    className="h-24 animate-pulse rounded-md bg-[hsl(var(--muted))]"
                  />
                ))}
              </div>
            ) : (
              <div className="grid grid-cols-2 gap-4">
                {scorecard
                  .filter((fw) =>
                    ["CIS_AZURE", "NIST_800_53", "ISO_27001", "PCI_DSS"].includes(
                      fw.framework_id,
                    ),
                  )
                  .map((fw) => {
                    const evaluated = fw.controls_total > 0;
                    return (
                      <button
                        key={fw.framework_id}
                        type="button"
                        onClick={() =>
                          navigate(`/compliance?framework=${fw.framework_id}`)
                        }
                        className="flex flex-col items-center gap-1 rounded-md p-2 text-center transition-colors hover:bg-[hsl(var(--accent)/0.08)]"
                        title={
                          evaluated
                            ? `${fw.controls_passed}/${fw.controls_total} controls passing · ${fw.open_findings} open finding${fw.open_findings === 1 ? "" : "s"}`
                            : "Not yet evaluated"
                        }
                      >
                        <ProgressRing
                          value={evaluated ? fw.score : 0}
                          label={fw.short_label}
                        />
                        <span className="text-[10px] text-[hsl(var(--muted-foreground))]">
                          {evaluated
                            ? `${fw.controls_passed}/${fw.controls_total} controls`
                            : "Not yet evaluated"}
                        </span>
                      </button>
                    );
                  })}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Third row: Recent activity + Data source health ──────────── */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Recent activity</CardTitle>
          </CardHeader>
          <CardContent>
            {metrics.recent.length === 0 ? (
              <p className="py-8 text-center text-sm text-[hsl(var(--muted-foreground))]">
                No activity yet.
              </p>
            ) : (
              <ul className="space-y-3">
                {metrics.recent.map((f, i) => {
                  const status = f.status ?? "OPEN";
                  const isApplied = status === "APPLIED";
                  const isResolved = status === "RESOLVED";
                  const Icon = isApplied ? Wrench : isResolved ? ShieldCheck : Activity;
                  const label = isApplied
                    ? "Remediation applied"
                    : isResolved
                      ? "Finding resolved"
                      : f.finding_type === "FINOPS"
                        ? "Cost finding detected"
                        : f.finding_type === "COMPLIANCE"
                          ? "Compliance check"
                          : "Security finding detected";
                  return (
                    <li key={f.finding_id} className="flex items-start gap-3 text-sm">
                      <div className="relative flex flex-col items-center">
                        <span className="mt-0.5 flex h-6 w-6 items-center justify-center rounded-full bg-[hsl(var(--accent)/0.15)] text-[hsl(var(--primary))]">
                          <Icon className="h-3.5 w-3.5" />
                        </span>
                        {i < metrics.recent.length - 1 && (
                          <span className="min-h-[12px] w-px flex-1 bg-[hsl(var(--border))]" />
                        )}
                      </div>
                      <div className="min-w-0 flex-1 pb-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate font-medium text-[hsl(var(--foreground))]">
                            {label}
                          </span>
                          <span className="shrink-0 text-[11px] text-[hsl(var(--muted-foreground))]">
                            {relativeTime(f.detected_at)}
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={() => setSelectedFinding(f)}
                          className="mt-0.5 truncate text-left text-xs text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--primary))] hover:underline"
                        >
                          {f.rule_name || f.rule_id} ·{" "}
                          {f.resource_snapshot?.resource_name ?? "resource"}
                        </button>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Data source health</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <DataSourceRow
              label="Tier 1 — Native"
              hint="Azure Resource Manager"
              status="connected"
            />
            <DataSourceRow
              label="Tier 2 — Free CSPM"
              hint="Defender for Cloud (free)"
              status={metrics.tier2Active ? "connected" : "not_connected"}
            />
            <DataSourceRow
              label="Tier 3 — Defender (paid)"
              hint="Deep telemetry"
              status={metrics.tier3Active ? "connected" : "not_connected"}
            />
            <p className="pt-1 text-[11px] text-[hsl(var(--muted-foreground))]">
              Tier 2 / 3 are optional. CloudGuardIQ never errors when these are
              unavailable — it gracefully degrades to native signals.
            </p>
          </CardContent>
        </Card>
      </div>

      {selectedFinding ? (
        <FindingDetailPanel
          finding={selectedFinding}
          onClose={() => { setSelectedFinding(null); refresh(); }}
        />
      ) : null}
    </div>
  );
}

function DataSourceRow({
  label,
  hint,
  status,
}: {
  label: string;
  hint: string;
  status: "connected" | "not_connected";
}) {
  const connected = status === "connected";
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="min-w-0">
        <div className="text-sm font-medium text-[hsl(var(--foreground))]">{label}</div>
        <div className="text-[11px] text-[hsl(var(--muted-foreground))]">{hint}</div>
      </div>
      <span
        className={cn(
          "inline-flex shrink-0 items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset",
          connected
            ? "bg-[hsl(var(--success)/0.12)] text-[hsl(var(--success))] ring-[hsl(var(--success)/0.3)]"
            : "bg-[hsl(var(--muted))] text-[hsl(var(--muted-foreground))] ring-[hsl(var(--border))]",
        )}
      >
        {connected ? (
          <CircleDot className="h-3 w-3" />
        ) : (
          <CircleSlash className="h-3 w-3" />
        )}
        {connected ? "Connected" : "Not connected"}
      </span>
    </div>
  );
}




