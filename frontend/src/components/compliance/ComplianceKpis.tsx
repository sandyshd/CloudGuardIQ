import { useMemo } from "react";
import { ShieldCheck, ShieldAlert, AlertOctagon, ListChecks } from "lucide-react";
import { StatCard } from "../common/StatCard";
import type { FindingResult } from "../../types";

interface ComplianceKpisProps {
  findings: FindingResult[];
}

function computeScore(findings: FindingResult[]): number {
  if (findings.length === 0) return 100;
  const failing = findings.filter(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH",
  ).length;
  return Math.round(((findings.length - failing) / findings.length) * 100);
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

  const scoreTone =
    stats.score >= 90
      ? "success"
      : stats.score >= 75
        ? "warning"
        : "danger";

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <StatCard
        label="Compliance score"
        value={`${stats.score}%`}
        hint={
          stats.score >= 90
            ? "Healthy posture"
            : stats.score >= 75
              ? "Some attention needed"
              : "Action required"
        }
        icon={<ShieldCheck className="h-4 w-4" />}
        tone={scoreTone}
      />
      <StatCard
        label="Frameworks tracked"
        value={stats.frameworks}
        hint={
          stats.frameworks === 0
            ? "No frameworks detected"
            : `${stats.frameworks} active`
        }
        icon={<ListChecks className="h-4 w-4" />}
        tone="brand"
      />
      <StatCard
        label="Open controls"
        value={stats.open}
        hint={
          stats.open === 0 ? "Nothing failing" : "Failing across frameworks"
        }
        icon={<ShieldAlert className="h-4 w-4" />}
        tone={stats.open === 0 ? "success" : "warning"}
      />
      <StatCard
        label="Critical / High"
        value={stats.criticalHigh}
        hint={
          stats.criticalHigh === 0
            ? "No urgent failures"
            : "Top priority remediation"
        }
        icon={<AlertOctagon className="h-4 w-4" />}
        tone={stats.criticalHigh > 0 ? "danger" : "default"}
      />
    </div>
  );
}
