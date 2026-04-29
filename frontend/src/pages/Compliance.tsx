import { useFindings } from "../hooks/useFindings";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { FrameworkScorecard } from "../components/compliance/FrameworkScorecard";
import { ControlList } from "../components/compliance/ControlList";
import { ReportHistory } from "../components/compliance/ReportHistory";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { EmptyState } from "../components/common/EmptyState";
import { Link2, ClipboardCheck } from "lucide-react";

export function Compliance() {
  const { findings, loading } = useFindings();
  const { subscriptions, loading: subsLoading } = useSubscriptions();

  if (loading || subsLoading) return <LoadingSpinner />;

  if (subscriptions.length === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">Compliance</h1>
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
        <h1 className="text-2xl font-bold">Compliance</h1>
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
      <h1 className="text-2xl font-bold">Compliance</h1>
      <div className="grid gap-4 md:grid-cols-2">
        <FrameworkScorecard findings={findings} />
        <ReportHistory />
      </div>
      <ControlList findings={findings} />
    </div>
  );
}
