import { useMemo } from "react";
import { ShieldCheck, ShieldAlert, AlertOctagon, ListChecks, ListX } from "lucide-react";
import { StatCard } from "../common/StatCard";
import type { FindingResult } from "../../types";
import type { FrameworkScore } from "../../api/compliance";

interface ComplianceKpisProps {
  findings: FindingResult[];
  /** Optional scorecard from /compliance/scorecard. When provided, surfaces a
   * deduplicated "Failing controls" tile (sum of unique rule ids that failed
   * across the evaluated framework set). */
  scorecard?: FrameworkScore[];
}

function computeScore(findings: FindingResult[]): number {
  if (findings.length === 0) return 100;
  const failing = findings.filter(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH",
  ).length;
  return Math.round(((findings.length - failing) / findings.length) * 100);
}

export function ComplianceKpis({ findings, scorecard }: ComplianceKpisProps) {
  const stats = useMemo(() => {
    const compliance = findings.filter((f) => f.compliance_frameworks.length > 0);
    const frameworks = new Set<string>();
    compliance.forEach((f) =>
      f.compliance_frameworks.forEach((fw) => frameworks.add(fw)),
    );
    const critical = compliance.filter((f) => f.severity === "CRITICAL").length;
    const high = compliance.filter((f) => f.severity === "HIGH").length;
    // ``controls_failed`` is per framework, so the same backing rule (and
    // therefore the same finding) appears in every framework it is mapped
    // to. We surface the raw sum because each row in the list below uses
    // the same convention -- the tile and the row totals reconcile.
    const failingControls = (scorecard ?? []).reduce(
      (acc, fw) => acc + fw.controls_failed,
      0,
    );
    return {
      score: computeScore(compliance),
      frameworks: frameworks.size,
      open: compliance.length,
      criticalHigh: critical + high,
      failingControls,
    };
  }, [findings, scorecard]);

  const scoreTone =
    stats.score >= 90
      ? "success"
      : stats.score >= 75
        ? "warning"
        : "danger";

  const showFailingControlsTile = (scorecard ?? []).length > 0;

  return (
    <div
      className={`grid gap-4 md:grid-cols-2 ${
        showFailingControlsTile ? "lg:grid-cols-5" : "lg:grid-cols-4"
      }`}
    >
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
        label="Open findings"
        value={stats.open}
        hint={
          stats.open === 0
            ? "Nothing failing"
            : "Unique findings · counted once across frameworks"
        }
        icon={<ShieldAlert className="h-4 w-4" />}
        tone={stats.open === 0 ? "success" : "warning"}
      />
      {showFailingControlsTile && (
        <StatCard
          label="Failing controls"
          value={stats.failingControls}
          hint={
            stats.failingControls === 0
              ? "All evaluated controls passing"
              : "Sum across frameworks · cross-mapped controls counted in each"
          }
          icon={<ListX className="h-4 w-4" />}
          tone={stats.failingControls > 0 ? "warning" : "success"}
        />
      )}
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

