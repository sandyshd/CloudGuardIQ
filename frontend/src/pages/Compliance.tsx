import { useState } from "react";
import { useFindings } from "../hooks/useFindings";
import { useComplianceScorecard } from "../hooks/useComplianceScorecard";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { ComplianceKpis } from "../components/compliance/ComplianceKpis";
import { FrameworkScorecard } from "../components/compliance/FrameworkScorecard";
import { ControlList } from "../components/compliance/ControlList";
import { ReportHistory } from "../components/compliance/ReportHistory";
import { FindingDetailPanel } from "../components/findings/FindingDetailPanel";
import { PageSkeleton } from "../components/common/PageSkeleton";
import { EmptyState } from "../components/common/EmptyState";
import { PageHeader } from "../components/common/PageHeader";
import { Link2, ClipboardCheck } from "lucide-react";
import type { FindingResult } from "../types";

export function Compliance() {
  const {
    subscriptions,
    selected: selectedSub,
    loading: subsLoading,
  } = useSubscriptions();
  const { findings, loading } = useFindings(selectedSub?.subscription_id);
  const { scorecard, loading: scorecardLoading } = useComplianceScorecard(
    selectedSub?.subscription_id,
  );
  const [framework, setFramework] = useState<string | null>(null);
  const [selected, setSelected] = useState<FindingResult | null>(null);

  if (loading || subsLoading) return <PageSkeleton />;

  const subtitle = selectedSub
    ? `Posture across linked frameworks · ${selectedSub.display_name || selectedSub.subscription_id}`
    : "Posture across CIS, NIST, ISO 27001, PCI-DSS, and SOC 2.";

  if (subscriptions.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader title="Compliance" subtitle={subtitle} />
        <EmptyState
          icon={<Link2 className="h-12 w-12" />}
          title="Link a subscription to start scanning"
          message="Compliance posture against frameworks like CIS, NIST, and SOC2 is calculated from scan results. Connect an Azure subscription on the Settings page to begin."
          primaryLabel="Go to Settings"
          primaryTo="/settings"
        />
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader title="Compliance" subtitle={subtitle} />
        <EmptyState
          icon={<ClipboardCheck className="h-12 w-12" />}
          title="No compliance data yet"
          message="Run a scan from the Findings page to evaluate your subscription against CIS, NIST, and SOC2 controls."
          primaryLabel="Go to Findings"
          primaryTo="/findings"
        />
        <ReportHistory />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Compliance" subtitle={subtitle} />

      <ComplianceKpis findings={findings} />

      <div>
        <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
          Frameworks · controls passing
        </h2>
        {scorecardLoading ? (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div
                key={i}
                className="h-28 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]"
              />
            ))}
          </div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {scorecard.map((fw) => {
              const evaluated = fw.controls_total > 0;
              const color =
                fw.score >= 90
                  ? "hsl(var(--success))"
                  : fw.score >= 75
                    ? "hsl(var(--warning))"
                    : fw.score >= 50
                      ? "hsl(var(--severity-high))"
                      : "hsl(var(--severity-critical))";
              return (
                <div
                  key={fw.framework_id}
                  className="flex flex-col rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4 shadow-sm"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold text-[hsl(var(--foreground))]">
                        {fw.short_label}
                      </div>
                      <div className="mt-0.5 text-[11px] text-[hsl(var(--muted-foreground))]">
                        {evaluated
                          ? `${fw.controls_passed}/${fw.controls_total} controls passing`
                          : "Not yet evaluated"}
                      </div>
                    </div>
                    <div className="text-right">
                      <div
                        className="text-2xl font-semibold leading-none tabular-nums"
                        style={{
                          color: evaluated ? color : "hsl(var(--muted-foreground))",
                        }}
                      >
                        {evaluated ? `${fw.score}%` : "—"}
                      </div>
                    </div>
                  </div>
                  <div className="mt-3 flex items-center justify-between text-[11px] text-[hsl(var(--muted-foreground))]">
                    <span>
                      {fw.open_findings} open finding
                      {fw.open_findings === 1 ? "" : "s"}
                    </span>
                    {evaluated && (
                      <span>
                        {fw.controls_failed} failing
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
        <p className="mt-2 text-[11px] text-[hsl(var(--muted-foreground))]">
          Score = controls passing / controls evaluated. Denominator is the set of
          controls CloudGuardIQ's rule registry actively evaluates for each
          framework, not the published catalogue size.
        </p>
      </div>

      <FrameworkScorecard
        findings={findings}
        selected={framework}
        onSelect={setFramework}
      />

      <ControlList
        findings={findings}
        framework={framework}
        onFrameworkChange={setFramework}
        onSelect={setSelected}
      />

      <ReportHistory />

      {selected && (
        <FindingDetailPanel
          finding={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

