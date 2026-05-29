import { useState } from "react";
import { FileText, Link2 } from "lucide-react";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { ReportHistory } from "../components/compliance/ReportHistory";
import { PageHeader } from "../components/common/PageHeader";
import { PageSkeleton } from "../components/common/PageSkeleton";
import { EmptyState } from "../components/common/EmptyState";

const FRAMEWORK_OPTIONS: { value: string; label: string }[] = [
  { value: "CIS", label: "CIS Microsoft Azure Foundations Benchmark" },
  { value: "NIST", label: "NIST 800-53" },
  { value: "ISO", label: "ISO 27001" },
  { value: "PCI", label: "PCI DSS" },
  { value: "SOC2", label: "SOC 2" },
  { value: "HIPAA", label: "HIPAA" },
];

export function Reports() {
  const {
    subscriptions,
    selected: selectedSub,
    loading: subsLoading,
  } = useSubscriptions();
  const [framework, setFramework] = useState<string>("CIS");

  if (subsLoading) return <PageSkeleton />;

  const subtitle = selectedSub
    ? `Executive summaries and compliance evidence · ${selectedSub.display_name || selectedSub.subscription_id}`
    : "Executive summaries and compliance evidence";

  if (subscriptions.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader title="Reports" subtitle={subtitle} />
        <EmptyState
          icon={<Link2 className="h-12 w-12" />}
          title="Link a subscription to generate reports"
          message="Compliance readiness reports are generated from scan results for a specific subscription. Connect an Azure subscription on the Settings page to begin."
          primaryLabel="Go to Settings"
          primaryTo="/settings"
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Reports" subtitle={subtitle} />

      <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-3">
            <div className="rounded-md bg-[hsl(var(--primary)/0.1)] p-2 text-[hsl(var(--primary))]">
              <FileText className="h-5 w-5" />
            </div>
            <div>
              <div className="text-sm font-medium">Generate a compliance readiness report</div>
              <div className="text-xs text-[hsl(var(--muted-foreground))]">
                Pick a framework and click <em>Generate readiness report</em> below. Output is an informational readiness assessment (not an audit) using the same scoring as the Compliance page for the active time range.
              </div>
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <span className="text-[hsl(var(--muted-foreground))]">Framework</span>
            <select
              value={framework}
              onChange={(e) => setFramework(e.target.value)}
              className="rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--background))] px-2 py-1.5 text-sm"
            >
              {FRAMEWORK_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      <ReportHistory
        subscriptionId={selectedSub?.subscription_id}
        framework={framework}
      />
    </div>
  );
}
