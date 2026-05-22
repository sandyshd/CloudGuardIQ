import { useMemo } from "react";
import { useFindings } from "../hooks/useFindings";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { WasteTable } from "../components/finops/WasteTable";
import { SavingsProjection } from "../components/finops/SavingsProjection";
import { LifecycleGenerator } from "../components/finops/LifecycleGenerator";
import { PageHeader } from "../components/common/PageHeader";
import { StatCard } from "../components/common/StatCard";
import { EmptyState } from "../components/common/EmptyState";
import {
  Link2,
  DollarSign,
  TrendingDown,
  Wallet,
  Boxes,
  CalendarDays,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Cell,
} from "recharts";

export function FinOps() {
  const { subscriptions, selected: selectedSub, loading: subsLoading } =
    useSubscriptions();
  const { findings, loading } = useFindings(selectedSub?.subscription_id);

  const finopsFindings = useMemo(
    () => findings.filter((f) => f.finding_type === "FINOPS"),
    [findings],
  );

  const totals = useMemo(() => {
    const monthly = finopsFindings.reduce((s, f) => s + f.waste_monthly_usd, 0);
    const resources = new Set(
      finopsFindings.map((f) => f.resource_snapshot?.id).filter(Boolean),
    ).size;
    const top = [...finopsFindings].sort(
      (a, b) => b.waste_monthly_usd - a.waste_monthly_usd,
    )[0];
    return { monthly, annual: monthly * 12, resources, top };
  }, [finopsFindings]);

  const byRule = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of finopsFindings) {
      const k = f.rule_name || f.rule_id || "Other";
      m.set(k, (m.get(k) ?? 0) + f.waste_monthly_usd);
    }
    return [...m.entries()]
      .map(([name, value]) => ({ name, value: Math.round(value * 100) / 100 }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);
  }, [finopsFindings]);

  const isLoading = loading || subsLoading;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Cost Governance" subtitle="Loading FinOps data..." />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <div
              key={i}
              className="h-32 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]"
            />
          ))}
        </div>
        <div className="h-72 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]" />
      </div>
    );
  }

  if (subscriptions.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Cost Governance"
          subtitle="Identify cost waste, model savings, and govern lifecycle policies."
        />
        <EmptyState
          icon={<Link2 className="h-12 w-12" />}
          title="Link a cloud account to start scanning"
          message="Connect an Azure subscription or AWS account on the Settings page to surface idle VMs, unattached disks, Elastic IPs, and other cost waste across clouds."
          primaryLabel="Go to Settings"
          primaryTo="/settings"
        />
      </div>
    );
  }

  if (finopsFindings.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Cost Governance"
          subtitle="Identify cost waste, model savings, and govern lifecycle policies."
        />
        <EmptyState
          icon={<DollarSign className="h-12 w-12" />}
          title="No FinOps findings yet"
          message="Run a scan from the Findings page to detect underutilized VMs, unattached disks, Elastic IPs, and savings opportunities across all connected clouds."
          primaryLabel="Go to Findings"
          primaryTo="/findings"
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cost Governance"
        subtitle={`${finopsFindings.length} optimization opportunities across ${totals.resources} resources in ${selectedSub?.display_name ?? "scope"}.`}
      />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Identified savings / mo"
          value={`$${totals.monthly.toFixed(2)}`}
          icon={<DollarSign className="h-4 w-4" />}
          tone="success"
          hint="Sum of all open FinOps findings"
        />
        <StatCard
          label="Annualized impact"
          value={`$${totals.annual.toFixed(0)}`}
          icon={<CalendarDays className="h-4 w-4" />}
          tone="brand"
          hint="12 \u00d7 monthly waste"
        />
        <StatCard
          label="Top opportunity"
          value={
            totals.top ? `$${totals.top.waste_monthly_usd.toFixed(2)}` : "—"
          }
          icon={<TrendingDown className="h-4 w-4" />}
          tone="warning"
          hint={
            totals.top?.rule_name ?? totals.top?.rule_id ?? "No findings"
          }
        />
        <StatCard
          label="Resources affected"
          value={totals.resources}
          icon={<Boxes className="h-4 w-4" />}
          tone="default"
          hint={`${finopsFindings.length} total findings`}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        {/* Top waste by rule */}
        <section className="rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-5 shadow-sm">
          <div className="mb-3 flex items-baseline justify-between gap-3">
            <div>
              <h2 className="text-[15px] font-semibold tracking-tight text-[hsl(var(--foreground))]">
                Top waste sources
              </h2>
              <p className="text-xs text-[hsl(var(--muted-foreground))]">
                Monthly USD by detection rule
              </p>
            </div>
            <span className="inline-flex items-center gap-1 text-xs text-[hsl(var(--muted-foreground))]">
              <Wallet className="h-3.5 w-3.5" />
              Top {byRule.length}
            </span>
          </div>
          {byRule.length === 0 ? (
            <div className="py-12 text-center text-sm text-[hsl(var(--muted-foreground))]">
              No waste detected.
            </div>
          ) : (
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={byRule}
                  layout="vertical"
                  margin={{ left: 8, right: 16, top: 4, bottom: 4 }}
                >
                  <CartesianGrid
                    horizontal={false}
                    stroke="hsl(var(--border))"
                    strokeDasharray="3 3"
                  />
                  <XAxis
                    type="number"
                    stroke="hsl(var(--muted-foreground))"
                    tick={{ fontSize: 11 }}
                    tickFormatter={(v: number) => `$${v}`}
                  />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={180}
                    stroke="hsl(var(--muted-foreground))"
                    tick={{ fontSize: 11 }}
                    interval={0}
                  />
                  <Tooltip
                    cursor={{ fill: "hsl(var(--muted) / 0.4)" }}
                    contentStyle={{
                      background: "hsl(var(--popover))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                    formatter={(v: number) => [`$${v.toFixed(2)} / mo`, "Waste"]}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {byRule.map((_, i) => (
                      <Cell
                        key={i}
                        fill={`hsl(var(--chart-${(i % 6) + 1}))`}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        <div className="space-y-4">
          <SavingsProjection findings={findings} />
          <LifecycleGenerator />
        </div>
      </div>

      <section className="rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] shadow-sm">
        <div className="border-b border-[hsl(var(--border))] px-5 py-3">
          <h2 className="text-[15px] font-semibold tracking-tight text-[hsl(var(--foreground))]">
            Waste detail
          </h2>
          <p className="text-xs text-[hsl(var(--muted-foreground))]">
            Sorted by monthly impact, highest first
          </p>
        </div>
        <WasteTable findings={findings} />
      </section>
    </div>
  );
}
