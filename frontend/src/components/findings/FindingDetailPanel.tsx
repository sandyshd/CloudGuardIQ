import { SeverityBadge } from "../common/SeverityBadge";
import { DataTierBadge } from "../common/DataTierBadge";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { X } from "lucide-react";
import type { FindingResult } from "../../types";
import { useNavigate } from "react-router-dom";

interface FindingDetailPanelProps {
  finding: FindingResult;
  onClose: () => void;
}

export function FindingDetailPanel({ finding, onClose }: FindingDetailPanelProps) {
  const navigate = useNavigate();

  return (
    <div className="fixed inset-y-0 right-0 w-[480px] border-l bg-[hsl(var(--background))] shadow-xl z-50 overflow-y-auto">
      <div className="flex items-center justify-between border-b p-4">
        <h2 className="text-lg font-semibold">Finding Details</h2>
        <Button variant="ghost" size="icon" onClick={onClose}><X className="h-4 w-4" /></Button>
      </div>
      <div className="p-4 space-y-4">
        <div>
          <h3 className="font-medium">{finding.rule_name || finding.rule_id}</h3>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-1">{finding.description}</p>
        </div>
        <div className="flex gap-2 items-center">
          <SeverityBadge severity={finding.severity} />
          <Badge variant="outline">{finding.finding_type}</Badge>
          {finding.resource_snapshot?.data_tier && <DataTierBadge tier={finding.resource_snapshot.data_tier} />}
        </div>
        {finding.resource_snapshot && (
          <div className="space-y-1 text-sm">
            <div><span className="font-medium">Resource:</span> {finding.resource_snapshot.resource_name}</div>
            <div><span className="font-medium">Type:</span> {finding.resource_snapshot.resource_type}</div>
            <div><span className="font-medium">Region:</span> {finding.resource_snapshot.region}</div>
            <div><span className="font-medium">Resource Group:</span> {finding.resource_snapshot.resource_group}</div>
          </div>
        )}
        {finding.waste_monthly_usd > 0 && (
          <div className="text-sm">
            <span className="font-medium">Monthly Waste:</span> ${finding.waste_monthly_usd.toFixed(2)}
          </div>
        )}
        {finding.compliance_frameworks.length > 0 && (
          <div>
            <span className="text-sm font-medium">Compliance:</span>
            <div className="flex gap-1 flex-wrap mt-1">
              {finding.compliance_frameworks.map((fw) => <Badge key={fw} variant="secondary">{fw}</Badge>)}
            </div>
          </div>
        )}
        {Object.keys(finding.evidence).length > 0 && (
          <div>
            <span className="text-sm font-medium">Evidence:</span>
            <pre className="mt-1 rounded bg-[hsl(var(--muted))] p-2 text-xs overflow-x-auto">
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>
          </div>
        )}
        <Button className="w-full" onClick={() => navigate(`/ai-fix?finding=${finding.finding_id}`)}>
          Get AI Remediation
        </Button>
      </div>
    </div>
  );
}
