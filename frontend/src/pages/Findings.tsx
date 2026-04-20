import { useState } from "react";
import { useFindings } from "../hooks/useFindings";
import { FindingTable } from "../components/findings/FindingTable";
import { FindingDetailPanel } from "../components/findings/FindingDetailPanel";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { Button } from "../components/ui/button";
import { Alert, AlertDescription } from "../components/ui/alert";
import type { FindingResult, Severity, FindingType } from "../types";

export function Findings() {
  const { findings, loading, error, refresh } = useFindings();
  const [selected, setSelected] = useState<FindingResult | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Severity | "ALL">("ALL");
  const [typeFilter, setTypeFilter] = useState<FindingType | "ALL">("ALL");

  const filtered = findings.filter((f) => {
    if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
    if (typeFilter !== "ALL" && f.finding_type !== typeFilter) return false;
    return true;
  });

  if (loading) return <LoadingSpinner />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Findings</h1>
        <Button onClick={refresh}>Refresh</Button>
      </div>

      {error && <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>}

      <div className="flex gap-2">
        <select
          className="rounded border px-3 py-2 text-sm"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Severity | "ALL")}
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFORMATIONAL">Informational</option>
        </select>
        <select
          className="rounded border px-3 py-2 text-sm"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value as FindingType | "ALL")}
        >
          <option value="ALL">All Types</option>
          <option value="SECURITY">Security</option>
          <option value="FINOPS">FinOps</option>
          <option value="COMPLIANCE">Compliance</option>
        </select>
      </div>

      <FindingTable findings={filtered} onSelect={setSelected} />

      {selected && <FindingDetailPanel finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
