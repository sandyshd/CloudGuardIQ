import { useFindings } from "../hooks/useFindings";
import { FrameworkScorecard } from "../components/compliance/FrameworkScorecard";
import { ControlList } from "../components/compliance/ControlList";
import { ReportHistory } from "../components/compliance/ReportHistory";
import { LoadingSpinner } from "../components/common/LoadingSpinner";

export function Compliance() {
  const { findings, loading } = useFindings();

  if (loading) return <LoadingSpinner />;

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
