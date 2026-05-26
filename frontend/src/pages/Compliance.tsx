import { useState } from "react";
import { useFindings } from "../hooks/useFindings";
import { useComplianceScorecard } from "../hooks/useComplianceScorecard";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { ComplianceKpis } from "../components/compliance/ComplianceKpis";
import { FrameworkPosture } from "../components/compliance/FrameworkPosture";
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

      <FrameworkPosture scorecard={scorecard} loading={scorecardLoading} />

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

