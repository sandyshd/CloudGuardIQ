import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { ShieldCheck, ShieldAlert, AlertOctagon, ListChecks } from "lucide-react";
import type { FindingResult } from "../../types";

interface ComplianceKpisProps {
  findings: FindingResult[];
}

// Severity-weighted compliance score, identical formula to the Dashboard
// MetricCard: percentage of findings that are NOT critical or high. With
// no findings the posture is treated as 100% (nothing failing).
function computeScore(findings: FindingResult[]): number {
  if (findings.length === 0) return 100;
  const failing = findings.filter(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH",
  ).length;
  return Math.round(((findings.length - failing) / findings.length) * 100);
}

function scoreTone(score: number): string {
  if (score >= 90) return "text-emerald-600";
  if (score >= 75) return "text-amber-600";
  if (score >= 50) return "text-orange-600";
  return "text-red-600";
}

export function ComplianceKpis({ findings }: ComplianceKpisProps) {
  const stats = useMemo(() => {
    const compliance = findings.filter((f) => f.compliance_frameworks.length > 0);
    const frameworks = new Set<string>();
    compliance.forEach((f) =>
      f.compliance_frameworks.forEach((fw) => frameworks.add(fw)),
    );
    const critical = compliance.filter((f) => f.severity === "CRITICAL").length;
    const high = compliance.filter((f) => f.severity === "HIGH").length;
    return {
      score: computeScore(compliance),
      frameworks: frameworks.size,
      open: compliance.length,
      criticalHigh: critical + high,
    };
  }, [findings]);

  const tiles: {
    title: string;
    value: string | number;
    icon: React.ReactNode;
    description: string;
    valueClass?: string;
  }[] = [
    {
      title: "Compliance Score",
      value: `${stats.score}%`,
      icon: <ShieldCheck className="h-4 w-4 text-emerald-500" />,
      description:
        stats.score >= 90
          ? "Healthy posture"
          : stats.score >= 75
            ? "Some attention needed"
            : "Action required",
      valueClass: scoreTone(stats.score),
    },
    {
      title: "Frameworks Tracked",
      value: stats.frameworks,
      icon: <ListChecks className="h-4 w-4 text-blue-500" />,
      description:
        stats.frameworks === 0
          ? "No frameworks detected"
          : `${stats.frameworks} active`,
    },
    {
      title: "Open Controls",
      value: stats.open,
      icon: <ShieldAlert className="h-4 w-4 text-amber-500" />,
      description:
        stats.open === 0 ? "Nothing failing" : "Failing across frameworks",
    },
    {
      title: "Critical / High",
      value: stats.criticalHigh,
      icon: <AlertOctagon className="h-4 w-4 text-red-500" />,
      description:
        stats.criticalHigh === 0
          ? "No urgent failures"
          : "Top priority remediation",
      valueClass: stats.criticalHigh > 0 ? "text-red-600" : undefined,
    },
  ];

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {tiles.map((t) => (
        <Card key={t.title}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-[hsl(var(--muted-foreground))]">
              {t.title}
            </CardTitle>
            {t.icon}
          </CardHeader>
          <CardContent>
            <div
              className={`text-3xl font-bold ${t.valueClass ?? ""}`}
            >
              {t.value}
            </div>
            <p className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
              {t.description}
            </p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
