import { useFindings } from "../hooks/useFindings";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { WasteTable } from "../components/finops/WasteTable";
import { SavingsProjection } from "../components/finops/SavingsProjection";
import { LifecycleGenerator } from "../components/finops/LifecycleGenerator";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { EmptyState } from "../components/common/EmptyState";
import { Link2, DollarSign } from "lucide-react";

export function FinOps() {
  const { subscriptions, selected: selectedSub, loading: subsLoading } = useSubscriptions();
  const { findings, loading } = useFindings(selectedSub?.subscription_id);

  if (loading || subsLoading) return <LoadingSpinner />;

  if (subscriptions.length === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">FinOps — Cost Governance</h1>
        <EmptyState
          icon={<Link2 className="h-12 w-12" />}
          title="Link a subscription to start scanning"
          message="Connect an Azure subscription on the Settings page to surface idle VMs, unattached disks, and other cost waste."
          primaryLabel="Go to Settings"
          primaryTo="/settings"
        />
      </div>
    );
  }

  const finopsFindings = findings.filter((f) => f.finding_type === "FINOPS");

  if (finopsFindings.length === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">FinOps — Cost Governance</h1>
        <EmptyState
          icon={<DollarSign className="h-12 w-12" />}
          title="No FinOps findings yet"
          message="Run a scan from the Findings page to detect underutilized VMs, unattached disks, and savings opportunities."
          primaryLabel="Go to Findings"
          primaryTo="/findings"
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">FinOps — Cost Governance</h1>
      <div className="grid gap-4 md:grid-cols-2">
        <SavingsProjection findings={findings} />
        <LifecycleGenerator />
      </div>
      <WasteTable findings={findings} />
    </div>
  );
}
