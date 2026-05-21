import { HealingEventLog } from "../components/healing/HealingEventLog";
import { MonitorStatus } from "../components/healing/MonitorStatus";
import { AgentConfig } from "../components/healing/AgentConfig";
import { EmptyState } from "../components/common/EmptyState";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { PageHeader } from "../components/common/PageHeader";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { Link2 } from "lucide-react";

export function SelfHeal() {
  const { subscriptions, loading } = useSubscriptions();

  if (loading) return <LoadingSpinner />;

  if (subscriptions.length === 0) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Self-healing"
          subtitle="Automated response to drift, threats, and policy violations."
        />
        <EmptyState
          icon={<Link2 className="h-12 w-12" />}
          title="Link a subscription to enable self-healing"
          message="Self-healing agents act on findings from your linked Azure subscriptions. Connect a subscription on the Settings page to configure healing policies."
          primaryLabel="Go to Settings"
          primaryTo="/settings"
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Self-healing"
        subtitle="Automated response to drift, threats, and policy violations."
      />
      <div className="grid gap-4 md:grid-cols-2">
        <MonitorStatus active={false} />
        <AgentConfig />
      </div>
      <HealingEventLog events={[]} />
    </div>
  );
}
