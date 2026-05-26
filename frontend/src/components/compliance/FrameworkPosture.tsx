import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, ShieldCheck, ShieldAlert } from "lucide-react";
import type { FrameworkScore } from "../../api/compliance";

interface FrameworkPostureProps {
  scorecard: FrameworkScore[];
  loading: boolean;
}

type SortKey = "score" | "failing" | "label";

/**
 * Parse a framework family prefix from a framework_id.
 *
 * The scorecard exposes ids like ``CIS_1.5``, ``NIST_SC-28``, ``SOC2_CC6.1``,
 * ``PCI_DSS_3.4`` and ``ISO_27001_A.9``. The family is the part before the
 * first underscore (or hyphen for NIST_SC-28 -> "NIST"). Falling back to
 * "Other" keeps the UI resilient to new frameworks the backend may emit.
 */
function familyOf(fw: FrameworkScore): string {
  const id = fw.framework_id || "";
  const head = id.split(/[_-]/)[0]?.toUpperCase() || "";
  switch (head) {
    case "CIS":
      return "CIS";
    case "NIST":
      return "NIST";
    case "SOC2":
    case "SOC":
      return "SOC 2";
    case "ISO":
      return "ISO 27001";
    case "PCI":
      return "PCI DSS";
    default:
      return head || "Other";
  }
}

function scoreColor(score: number, evaluated: boolean): string {
  if (!evaluated) return "hsl(var(--muted-foreground))";
  if (score >= 90) return "hsl(var(--success))";
  if (score >= 75) return "hsl(var(--warning))";
  if (score >= 50) return "hsl(var(--severity-high))";
  return "hsl(var(--severity-critical))";
}

/** Tier label used for the family ring and per-row dot colour. */
function statusBucket(fw: FrameworkScore): "pass" | "warn" | "risk" | "fail" {
  if (fw.controls_total === 0) return "warn";
  if (fw.score >= 90) return "pass";
  if (fw.score >= 75) return "warn";
  if (fw.score >= 50) return "risk";
  return "fail";
}

const BUCKET_COLOR: Record<ReturnType<typeof statusBucket>, string> = {
  pass: "hsl(var(--success))",
  warn: "hsl(var(--warning))",
  risk: "hsl(var(--severity-high))",
  fail: "hsl(var(--severity-critical))",
};

/**
 * Dense, family-grouped framework posture view.
 *
 * Replaces the previous 19-tall grid of large framework cards with:
 *
 * 1. **Family tiles** (5 wide max) -- one tile per framework family (CIS,
 *    NIST, SOC 2, ...). Each tile shows the aggregate score, a strip of
 *    per-framework status dots, and acts as a filter for the list below.
 * 2. **Compact list** -- one ~32 px row per framework with inline progress
 *    bar, severity dots, score chip, and open-finding count. Sortable.
 *
 * This compresses what used to be ~5 screens of cards into roughly one
 * screen while surfacing more information per framework (severity mix,
 * family aggregation) than the old layout.
 */
export function FrameworkPosture({ scorecard, loading }: FrameworkPostureProps) {
  const [activeFamily, setActiveFamily] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("score");
  const [sortAsc, setSortAsc] = useState(true);

  const families = useMemo(() => {
    const byFamily = new Map<string, FrameworkScore[]>();
    for (const fw of scorecard) {
      const fam = familyOf(fw);
      const list = byFamily.get(fam) ?? [];
      list.push(fw);
      byFamily.set(fam, list);
    }
    return Array.from(byFamily.entries())
      .map(([name, items]) => {
        const evaluated = items.filter((i) => i.controls_total > 0);
        const totalCtrls = evaluated.reduce((a, b) => a + b.controls_total, 0);
        const passedCtrls = evaluated.reduce((a, b) => a + b.controls_passed, 0);
        const aggScore = totalCtrls > 0 ? Math.round((passedCtrls / totalCtrls) * 100) : 0;
        const open = items.reduce((a, b) => a + b.open_findings, 0);
        return { name, items, aggScore, open, evaluatedCount: evaluated.length, totalCtrls };
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [scorecard]);

  const filtered = useMemo(() => {
    const base = activeFamily
      ? scorecard.filter((fw) => familyOf(fw) === activeFamily)
      : scorecard;
    const sorted = [...base].sort((a, b) => {
      let cmp = 0;
      if (sortKey === "score") cmp = a.score - b.score;
      else if (sortKey === "failing") cmp = a.controls_failed - b.controls_failed;
      else cmp = a.short_label.localeCompare(b.short_label);
      return sortAsc ? cmp : -cmp;
    });
    return sorted;
  }, [scorecard, activeFamily, sortKey, sortAsc]);

  if (loading) {
    return (
      <div className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <div
              key={i}
              className="h-24 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]"
            />
          ))}
        </div>
        <div className="h-64 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]" />
      </div>
    );
  }

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc((v) => !v);
    else {
      setSortKey(key);
      setSortAsc(key === "label");
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-[11px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
          Frameworks · controls passing
        </h2>
        <div className="flex items-center gap-2 text-[11px] text-[hsl(var(--muted-foreground))]">
          {activeFamily && (
            <button
              type="button"
              onClick={() => setActiveFamily(null)}
              className="rounded-full border border-[hsl(var(--border))] px-2 py-0.5 hover:bg-[hsl(var(--muted))]"
            >
              Clear filter: {activeFamily}
            </button>
          )}
          <button
            type="button"
            onClick={() => setCollapsed((v) => !v)}
            className="flex items-center gap-1 rounded-full border border-[hsl(var(--border))] px-2 py-0.5 hover:bg-[hsl(var(--muted))]"
            aria-expanded={!collapsed}
          >
            {collapsed ? (
              <>
                <ChevronRight className="h-3.5 w-3.5" /> Expand list
              </>
            ) : (
              <>
                <ChevronDown className="h-3.5 w-3.5" /> Collapse list
              </>
            )}
          </button>
        </div>
      </div>

      {/* Family summary tiles */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
        {families.map((fam) => {
          const isActive = activeFamily === fam.name;
          const color = scoreColor(fam.aggScore, fam.totalCtrls > 0);
          return (
            <button
              key={fam.name}
              type="button"
              onClick={() =>
                setActiveFamily((current) => (current === fam.name ? null : fam.name))
              }
              className={`flex flex-col rounded-[var(--radius)] border bg-[hsl(var(--card))] p-3 text-left shadow-sm transition hover:border-[hsl(var(--ring))] ${
                isActive
                  ? "border-[hsl(var(--ring))] ring-2 ring-[hsl(var(--ring))]/30"
                  : "border-[hsl(var(--border))]"
              }`}
              aria-pressed={isActive}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold text-[hsl(var(--foreground))]">
                    {fam.name}
                  </div>
                  <div className="mt-0.5 text-[11px] text-[hsl(var(--muted-foreground))]">
                    {fam.items.length} framework{fam.items.length === 1 ? "" : "s"}
                    {fam.open > 0 && (
                      <>
                        {" · "}
                        <span className="text-[hsl(var(--severity-high))]">
                          {fam.open} open
                        </span>
                      </>
                    )}
                  </div>
                </div>
                <div
                  className="text-xl font-semibold leading-none tabular-nums"
                  style={{ color }}
                  aria-label={`Aggregate score ${fam.aggScore}%`}
                >
                  {fam.totalCtrls > 0 ? `${fam.aggScore}%` : "—"}
                </div>
              </div>
              {/* Per-framework status dot strip — at-a-glance posture */}
              <div className="mt-3 flex flex-wrap gap-1">
                {fam.items.map((fw) => (
                  <span
                    key={fw.framework_id}
                    title={`${fw.short_label}: ${fw.controls_total > 0 ? fw.score + "%" : "not evaluated"}`}
                    className="h-1.5 w-4 rounded-full"
                    style={{ backgroundColor: BUCKET_COLOR[statusBucket(fw)] }}
                  />
                ))}
              </div>
            </button>
          );
        })}
      </div>

      {/* Compact framework list */}
      {!collapsed && (
        <div className="overflow-hidden rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] shadow-sm">
          <div className="grid grid-cols-[1fr_120px_120px_70px] items-center gap-3 border-b border-[hsl(var(--border))] bg-[hsl(var(--muted))]/40 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
            <button
              type="button"
              className="text-left hover:text-[hsl(var(--foreground))]"
              onClick={() => toggleSort("label")}
            >
              Framework {sortKey === "label" ? (sortAsc ? "↑" : "↓") : ""}
            </button>
            <div className="hidden sm:block">Severity mix</div>
            <button
              type="button"
              className="hidden text-left hover:text-[hsl(var(--foreground))] sm:block"
              onClick={() => toggleSort("failing")}
              title="Findings in this framework only. A finding cross-mapped to multiple frameworks is counted in each — so this column can sum higher than the 'Open findings' KPI above, which deduplicates."
            >
              In this framework {sortKey === "failing" ? (sortAsc ? "↑" : "↓") : ""}
            </button>
            <button
              type="button"
              className="text-right hover:text-[hsl(var(--foreground))]"
              onClick={() => toggleSort("score")}
            >
              Score {sortKey === "score" ? (sortAsc ? "↑" : "↓") : ""}
            </button>
          </div>
          {filtered.length === 0 ? (
            <div className="px-3 py-6 text-center text-[12px] text-[hsl(var(--muted-foreground))]">
              No frameworks match the current filter.
            </div>
          ) : (
            <ul className="divide-y divide-[hsl(var(--border))]">
              {filtered.map((fw) => {
                const evaluated = fw.controls_total > 0;
                const color = scoreColor(fw.score, evaluated);
                const pct = evaluated ? Math.max(2, fw.score) : 0;
                const sb = fw.severity_breakdown;
                return (
                  <li
                    key={fw.framework_id}
                    className="grid grid-cols-[1fr_120px_120px_70px] items-center gap-3 px-3 py-2 text-[12px]"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        {evaluated && fw.score >= 90 ? (
                          <ShieldCheck
                            className="h-3.5 w-3.5 shrink-0"
                            style={{ color }}
                          />
                        ) : (
                          <ShieldAlert
                            className="h-3.5 w-3.5 shrink-0"
                            style={{ color }}
                          />
                        )}
                        <span className="truncate font-medium text-[hsl(var(--foreground))]">
                          {fw.short_label}
                        </span>
                        <span className="truncate text-[11px] text-[hsl(var(--muted-foreground))]">
                          · {fw.controls_passed}/{fw.controls_total}
                        </span>
                      </div>
                      <div
                        className="mt-1 h-1 w-full overflow-hidden rounded-full bg-[hsl(var(--muted))]"
                        role="progressbar"
                        aria-valuenow={evaluated ? fw.score : 0}
                        aria-valuemin={0}
                        aria-valuemax={100}
                      >
                        <div
                          className="h-full rounded-full"
                          style={{ width: `${pct}%`, backgroundColor: color }}
                        />
                      </div>
                    </div>
                    {/* Severity mini-chips */}
                    <div className="hidden items-center gap-1 sm:flex">
                      {sb.critical > 0 && (
                        <span
                          className="rounded px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-white"
                          style={{ backgroundColor: "hsl(var(--severity-critical))" }}
                          title="Critical"
                        >
                          {sb.critical}
                        </span>
                      )}
                      {sb.high > 0 && (
                        <span
                          className="rounded px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-white"
                          style={{ backgroundColor: "hsl(var(--severity-high))" }}
                          title="High"
                        >
                          {sb.high}
                        </span>
                      )}
                      {sb.medium > 0 && (
                        <span
                          className="rounded px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-white"
                          style={{ backgroundColor: "hsl(var(--severity-medium))" }}
                          title="Medium"
                        >
                          {sb.medium}
                        </span>
                      )}
                      {sb.low > 0 && (
                        <span
                          className="rounded px-1.5 py-0.5 text-[10px] font-semibold tabular-nums text-white"
                          style={{ backgroundColor: "hsl(var(--severity-low))" }}
                          title="Low"
                        >
                          {sb.low}
                        </span>
                      )}
                      {sb.critical + sb.high + sb.medium + sb.low === 0 && (
                        <span className="text-[11px] text-[hsl(var(--muted-foreground))]">
                          —
                        </span>
                      )}
                    </div>
                    <div
                      className="hidden text-[11px] tabular-nums text-[hsl(var(--muted-foreground))] sm:block"
                      title="Findings tagged to this framework (cross-mapped findings appear in multiple rows)."
                    >
                      {fw.open_findings} in framework
                    </div>
                    <div
                      className="text-right text-sm font-semibold tabular-nums"
                      style={{ color }}
                    >
                      {evaluated ? `${fw.score}%` : "—"}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}

      <p className="text-[11px] text-[hsl(var(--muted-foreground))]">
        Score = controls passing / controls evaluated. Denominator is the set of
        controls CloudGuardIQ&apos;s rule registry actively evaluates for each
        framework, not the published catalogue size. Click a family tile to
        filter the list below.
      </p>
    </div>
  );
}
