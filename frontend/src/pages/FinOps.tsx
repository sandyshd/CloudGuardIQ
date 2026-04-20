import { useFindings } from "../hooks/useFindings";
import { WasteTable } from "../components/finops/WasteTable";
import { SavingsProjection } from "../components/finops/SavingsProjection";
import { LifecycleGenerator } from "../components/finops/LifecycleGenerator";
import { LoadingSpinner } from "../components/common/LoadingSpinner";

export function FinOps() {
  const { findings, loading } = useFindings();

  if (loading) return <LoadingSpinner />;

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
