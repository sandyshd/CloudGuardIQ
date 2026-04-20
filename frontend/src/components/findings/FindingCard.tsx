import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { SeverityBadge } from "../common/SeverityBadge";
import { Badge } from "../ui/badge";
import type { FindingResult } from "../../types";

interface FindingCardProps {
  finding: FindingResult;
  onClick: () => void;
}

export function FindingCard({ finding, onClick }: FindingCardProps) {
  return (
    <Card className="cursor-pointer hover:shadow-md transition-shadow" onClick={onClick}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm">{finding.rule_name || finding.rule_id}</CardTitle>
          <SeverityBadge severity={finding.severity} />
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-[hsl(var(--muted-foreground))] mb-2">{finding.description}</p>
        <div className="flex gap-1 flex-wrap">
          <Badge variant="outline">{finding.finding_type}</Badge>
          {finding.compliance_frameworks.map((fw) => (
            <Badge key={fw} variant="secondary">{fw}</Badge>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
