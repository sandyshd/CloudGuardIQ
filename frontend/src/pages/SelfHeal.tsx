import { HealingEventLog } from "../components/healing/HealingEventLog";
import { MonitorStatus } from "../components/healing/MonitorStatus";
import { AgentConfig } from "../components/healing/AgentConfig";

export function SelfHeal() {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Self-Healing</h1>
      <div className="grid gap-4 md:grid-cols-2">
        <MonitorStatus active={false} />
        <AgentConfig />
      </div>
      <HealingEventLog events={[]} />
    </div>
  );
}
