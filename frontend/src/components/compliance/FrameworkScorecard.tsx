import { useMemo } from "react";
import {
  RadialBarChart,
  RadialBar,
  PolarAngleAxis,
  ResponsiveContainer,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { cn } from "../../lib/utils";
import type { FindingResult, Severity } from "../../types";

interface FrameworkScorecardProps {
  findings: FindingResult[];
  selected: string | null;
  onSelect: (framework: string | null) => void;
}

interface FrameworkStats {
  name: string;
  total: number;
  bySeverity: Record<Severity, number>;
  score: number;
}

function buildStats(findings: FindingResult[]): FrameworkStats[] {
  const map = new Map<string, FrameworkStats>();
  findings.forEach((f) => {
    f.compliance_frameworks.forEach((fw) => {
      let stat = map.get(fw);
      if (!stat) {
        stat = {
          name: fw,
          total: 0,
          bySeverity: {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
            INFORMATIONAL: 0,
          },
          score: 100,
        };
        map.set(fw, stat);
      }
      stat.total += 1;
      stat.bySeverity[f.severity] += 1;
    });
  });
  // Compute score after counts settle: % of findings that are NOT
  // critical/high. Same formula used by ComplianceKpis + Dashboard.
  for (const stat of map.values()) {
    const failing = stat.bySeverity.CRITICAL + stat.bySeverity.HIGH;
    stat.score =
      stat.total === 0
        ? 100
        : Math.round(((stat.total - failing) / stat.total) * 100);
  }
  // Sort: worst posture first, then alphabetically.
  return [...map.values()].sort(
    (a, b) => a.score - b.score || a.name.localeCompare(b.name),
  );
}

function scoreColour(score: number): string {
  if (score >= 90) return "#10b981"; // emerald
  if (score >= 75) return "#f59e0b"; // amber
  if (score >= 50) return "#f97316"; // orange
  return "#dc2626"; // red
}

const SEV_COLOURS: Record<Severity, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#3b82f6",
  INFORMATIONAL: "#9ca3af",
};

const SEV_ORDER: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL",
];

function SeverityStrip({ stat }: { stat: FrameworkStats }) {
  const total = stat.total;
  if (total === 0) {
    return (
      <div className="text-xs text-[hsl(var(--muted-foreground))]">
        No findings
      </div>
    );
  }
  return (
    <div className="space-y-2">
      <div className="flex h-2 w-full overflow-hidden rounded-full bg-[hsl(var(--muted))]">
        {SEV_ORDER.map((sev) => {
          const c = stat.bySeverity[sev];
          if (c === 0) return null;
          const pct = (c / total) * 100;
          return (
            <div
              key={sev}
              style={{ width: `${pct}%`, backgroundColor: SEV_COLOURS[sev] }}
              title={`${sev}: ${c}`}
            />
          );
        })}
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs">
        {SEV_ORDER.filter((sev) => stat.bySeverity[sev] > 0).map((sev) => (
          <span key={sev} className="flex items-center gap-1">
            <span
              className="inline-block h-2 w-2 rounded-full"
              style={{ backgroundColor: SEV_COLOURS[sev] }}
            />
            <span className="text-[hsl(var(--muted-foreground))]">
              {sev[0] + sev.slice(1).toLowerCase()}
            </span>
            <span className="font-semibold">{stat.bySeverity[sev]}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

function FrameworkCard({
  stat,
  active,
  onClick,
}: {
  stat: FrameworkStats;
  active: boolean;
  onClick: () => void;
}) {
  const colour = scoreColour(stat.score);
  const data = [{ name: "score", value: stat.score, fill: colour }];
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "group flex w-full flex-col rounded-lg border bg-[hsl(var(--background))] p-4 text-left cursor-pointer transition-shadow hover:shadow-md focus:outline-none focus:ring-2 focus:ring-blue-500",
        active
          ? "border-blue-500 ring-1 ring-blue-500 shadow-sm"
          : "border-[hsl(var(--border))]",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-semibold">{stat.name}</div>
          <div className="mt-0.5 text-xs text-[hsl(var(--muted-foreground))]">
            {stat.total} open control{stat.total === 1 ? "" : "s"}
          </div>
        </div>
        <div className="relative h-20 w-20 shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart
              cx="50%"
              cy="50%"
              innerRadius="70%"
              outerRadius="100%"
              barSize={8}
              data={data}
              startAngle={90}
              endAngle={-270}
            >
              <PolarAngleAxis
                type="number"
                domain={[0, 100]}
                angleAxisId={0}
                tick={false}
              />
              <RadialBar
                background={{ fill: "hsl(var(--muted))" }}
                dataKey="value"
                cornerRadius={4}
              />
            </RadialBarChart>
          </ResponsiveContainer>
          <div
            className="pointer-events-none absolute inset-0 flex items-center justify-center text-sm font-bold"
            style={{ color: colour }}
          >
            {stat.score}%
          </div>
        </div>
      </div>
      <div className="mt-3">
        <SeverityStrip stat={stat} />
      </div>
      <div className="mt-3 text-xs text-[hsl(var(--muted-foreground))] opacity-0 transition-opacity group-hover:opacity-100">
        {active ? "Click to clear filter" : "Click to filter controls"}
      </div>
    </button>
  );
}

export function FrameworkScorecard({
  findings,
  selected,
  onSelect,
}: FrameworkScorecardProps) {
  const stats = useMemo(() => buildStats(findings), [findings]);

  if (stats.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Frameworks</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-[hsl(var(--muted-foreground))]">
            No findings are tagged with a compliance framework yet.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
          Frameworks
        </h2>
        {selected && (
          <button
            type="button"
            onClick={() => onSelect(null)}
            className="text-xs font-medium text-blue-600 hover:underline"
          >
            Clear framework filter
          </button>
        )}
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {stats.map((stat) => (
          <FrameworkCard
            key={stat.name}
            stat={stat}
            active={selected === stat.name}
            onClick={() =>
              onSelect(selected === stat.name ? null : stat.name)
            }
          />
        ))}
      </div>
    </div>
  );
}
