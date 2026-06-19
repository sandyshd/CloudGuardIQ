import { useCallback, useEffect, useMemo, useState } from "react";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { PageHeader } from "../components/common/PageHeader";
import { StatCard } from "../components/common/StatCard";
import { EmptyState } from "../components/common/EmptyState";
import { PageSkeleton } from "../components/common/PageSkeleton";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../components/ui/table";
import {
  getAllocation,
  getAnomalies,
  getTagCoverage,
  getUnitEconomics,
} from "../api/finops";
import { toFriendlyMessage } from "../lib/errors";
import type {
  AllocationSummary,
  SpendAnomaly,
  TagCoverage,
  UnitEconomics,
} from "../types";
import {
  BarChart,
  Bar,
  Cell,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  PieChart,
  Boxes,
  AlertTriangle,
  Tags,
  Sparkles,
} from "lucide-react";

const DIMENSIONS = ["team", "app", "environment", "cost_center"] as const;

function usd(value: number): string {
  return value.toLocaleString("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  });
}

const SEVERITY_TONE: Record<string, string> = {
  CRITICAL: "text-[hsl(var(--severity-critical))]",
  HIGH: "text-[hsl(var(--warning))]",
  MEDIUM: "text-[hsl(var(--muted-foreground))]",
};

export function Optimization() {
  const { selected: selectedSub, loading: subsLoading } = useSubscriptions();
  const subId = selectedSub?.subscription_id;

  const [dimension, setDimension] = useState<string>("team");
  const [allocation, setAllocation] = useState<AllocationSummary | null>(null);
  const [coverage, setCoverage] = useState<TagCoverage>({});
  const [anomalies, setAnomalies] = useState<SpendAnomaly[]>([]);
  const [unitCount, setUnitCount] = useState<number>(100);
  const [unitLabel, setUnitLabel] = useState<string>("customer");
  const [unitEcon, setUnitEcon] = useState<UnitEconomics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!subId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [alloc, cov, anoms, econ] = await Promise.all([
        getAllocation(subId, dimension),
        getTagCoverage(subId),
        getAnomalies(subId),
        getUnitEconomics(subId, unitCount, unitLabel),
      ]);
      setAllocation(alloc);
      setCoverage(cov);
      setAnomalies(anoms);
      setUnitEcon(econ);
    } catch (err) {
      setError(toFriendlyMessage(err, "Failed to load optimization data"));
    } finally {
      setLoading(false);
    }
  }, [subId, dimension, unitCount, unitLabel]);

  useEffect(() => {
    load();
  }, [load]);

  const chartData = useMemo(
    () =>
      (allocation?.groups ?? []).slice(0, 8).map((g) => ({
        name: g.key,
        value: Math.round(g.cost * 100) / 100,
      })),
    [allocation],
  );

  if (subsLoading || loading) {
    return <PageSkeleton />;
  }

  if (!subId) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Cost Optimization"
          subtitle="Allocation, tag coverage, anomalies, and unit economics."
        />
        <EmptyState
          icon={<Sparkles className="h-7 w-7" />}
          title="Select a subscription"
          message="Choose a subscription to view cost allocation and optimization insights."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cost Optimization"
        subtitle="Showback/chargeback allocation, tag coverage, anomalies, and unit economics."
      />

      {error ? (
        <div className="rounded-[var(--radius)] border border-[hsl(var(--severity-critical)/0.4)] bg-[hsl(var(--severity-critical)/0.08)] p-4 text-sm text-[hsl(var(--severity-critical))]">
          {error}
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Allocated spend"
          value={usd(allocation?.allocated_cost ?? 0)}
          hint={`by ${dimension}`}
          icon={<PieChart className="h-5 w-5" />}
          tone="brand"
        />
        <StatCard
          label="Unallocated spend"
          value={usd(allocation?.unallocated_cost ?? 0)}
          hint="missing allocation tag"
          icon={<Tags className="h-5 w-5" />}
          tone={allocation && allocation.unallocated_cost > 0 ? "warning" : "default"}
        />
        <StatCard
          label="Tag coverage"
          value={`${Math.round((allocation?.coverage_pct ?? 0) * 100)}%`}
          hint={`${dimension} dimension`}
          icon={<Boxes className="h-5 w-5" />}
          tone={(allocation?.coverage_pct ?? 0) >= 0.8 ? "success" : "warning"}
        />
        <StatCard
          label="Spend anomalies"
          value={anomalies.length}
          hint="vs rolling baseline"
          icon={<AlertTriangle className="h-5 w-5" />}
          tone={anomalies.length > 0 ? "danger" : "success"}
        />
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>Cost allocation</CardTitle>
          <div className="flex items-center gap-1">
            {DIMENSIONS.map((d) => (
              <button
                key={d}
                onClick={() => setDimension(d)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                  dimension === d
                    ? "bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))]"
                    : "text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent)/0.12)]"
                }`}
              >
                {d}
              </button>
            ))}
          </div>
        </CardHeader>
        <CardContent>
          {chartData.length === 0 ? (
            <p className="py-8 text-center text-sm text-[hsl(var(--muted-foreground))]">
              No allocated spend for this dimension.
            </p>
          ) : (
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} layout="vertical" margin={{ left: 24 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" horizontal={false} />
                  <XAxis type="number" tickFormatter={(v) => usd(Number(v))} stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <YAxis type="category" dataKey="name" width={120} stroke="hsl(var(--muted-foreground))" fontSize={12} />
                  <Tooltip
                    formatter={(v) => usd(Number(v))}
                    contentStyle={{
                      background: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "var(--radius)",
                    }}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {chartData.map((_, i) => (
                      <Cell key={i} fill="hsl(var(--primary))" />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Tag coverage by dimension</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Dimension</TableHead>
                  <TableHead className="text-right">Coverage</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {Object.entries(coverage).length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={2} className="text-center text-[hsl(var(--muted-foreground))]">
                      No coverage data.
                    </TableCell>
                  </TableRow>
                ) : (
                  Object.entries(coverage).map(([dim, pct]) => (
                    <TableRow key={dim}>
                      <TableCell className="font-medium">{dim}</TableCell>
                      <TableCell className="text-right">
                        <span className={pct >= 0.8 ? "text-[hsl(var(--success))]" : "text-[hsl(var(--warning))]"}>
                          {Math.round(pct * 100)}%
                        </span>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Unit economics</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1 text-xs text-[hsl(var(--muted-foreground))]">
                Units
                <input
                  type="number"
                  min={0}
                  value={unitCount}
                  onChange={(e) => setUnitCount(Math.max(0, Number(e.target.value)))}
                  className="h-9 w-28 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 text-sm text-[hsl(var(--foreground))]"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-[hsl(var(--muted-foreground))]">
                Label
                <input
                  type="text"
                  value={unitLabel}
                  onChange={(e) => setUnitLabel(e.target.value)}
                  className="h-9 w-36 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 text-sm text-[hsl(var(--foreground))]"
                />
              </label>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="rounded-[var(--radius)] border border-[hsl(var(--border))] p-4">
                <div className="text-xs uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
                  Cost / {unitEcon?.unit_label ?? unitLabel}
                </div>
                <div className="mt-1 text-2xl font-semibold">
                  {usd(unitEcon?.cost_per_unit ?? 0)}
                </div>
                <div className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
                  MTD {usd(unitEcon?.total_cost ?? 0)}
                </div>
              </div>
              <div className="rounded-[var(--radius)] border border-[hsl(var(--border))] p-4">
                <div className="text-xs uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
                  Projected / {unitEcon?.unit_label ?? unitLabel}
                </div>
                <div className="mt-1 text-2xl font-semibold">
                  {usd(unitEcon?.projected_cost_per_unit ?? 0)}
                </div>
                <div className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
                  Month-end {usd(unitEcon?.projected_month_end_cost ?? 0)}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Spend anomalies</CardTitle>
        </CardHeader>
        <CardContent>
          {anomalies.length === 0 ? (
            <p className="py-8 text-center text-sm text-[hsl(var(--muted-foreground))]">
              No anomalies detected against the rolling baseline.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Date</TableHead>
                  <TableHead className="text-right">Observed</TableHead>
                  <TableHead className="text-right">Baseline</TableHead>
                  <TableHead className="text-right">z-score</TableHead>
                  <TableHead>Severity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {anomalies.map((a) => (
                  <TableRow key={`${a.key}-${a.date}`}>
                    <TableCell className="font-medium">{a.date}</TableCell>
                    <TableCell className="text-right">{usd(a.observed_cost)}</TableCell>
                    <TableCell className="text-right text-[hsl(var(--muted-foreground))]">
                      {usd(a.baseline_mean)}
                    </TableCell>
                    <TableCell className="text-right">{a.z_score.toFixed(1)}</TableCell>
                    <TableCell>
                      <span className={`font-medium ${SEVERITY_TONE[a.severity] ?? ""}`}>
                        {a.severity}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
