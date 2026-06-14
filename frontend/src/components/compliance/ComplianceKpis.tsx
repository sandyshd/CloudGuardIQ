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

/**
 * Industry-standard compliance readiness score: passing controls / total
 * controls evaluated, pooled across every framework on the scorecard. This
 * is the SAME methodology used by the per-framework posture tiles and the
 * PDF readiness reports (``compute_scorecard`` on the backend), so the
 * headline number now reconciles with both instead of diverging from them.
 *
 * Cross-mapped controls are counted within each framework they belong to,
 * matching the "Failing controls" tile convention below.
 */
function aggregateControlScore(scorecard: FrameworkScore[]): number {
  const totals = scorecard.reduce(
    (acc, fw) => {
      acc.passed += fw.controls_passed;
      acc.total += fw.controls_total;
      return acc;
    },
    { passed: 0, total: 0 },
  );
  if (totals.total === 0) return 100;
  return Math.round((totals.passed / totals.total) * 100);
}

export function ComplianceKpis({ findings, scorecard }: ComplianceKpisProps) {
  const stats = useMemo(() => {
    // Match the backend definition of "open" (status === OPEN) so the
    // KPI strip reconciles with the scorecard's per-framework counts
    // and the "Failed controls" table below. Findings with no framework
    // tags are excluded -- this page is about framework posture.
    const compliance = findings.filter(
      (f) => f.compliance_frameworks.length > 0 && f.status === "OPEN",
    );
    // "Frameworks tracked" must mean evaluated frameworks (CIS, NIST, ...),
    // not the distinct control-level tags ("CIS_3.1", "NIST_SC-28", ...) a
    // finding carries. When the scorecard is present we count the framework
    // rows that actually evaluate at least one control so this tile
    // reconciles with the posture tiles below and the PDF reports. The
    // tag-set is only a fallback while the scorecard loads.
    const frameworkTags = new Set<string>();
    compliance.forEach((f) =>
      f.compliance_frameworks.forEach((fw) => frameworkTags.add(fw)),
    );
    const evaluatedFrameworks =
      scorecard && scorecard.length > 0
        ? scorecard.filter((fw) => fw.controls_total > 0).length
        : frameworkTags.size;
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
      score:
        scorecard && scorecard.length > 0
          ? aggregateControlScore(scorecard)
          : computeScore(compliance),
      frameworks: evaluatedFrameworks,
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

