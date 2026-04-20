import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { SeverityBadge } from "../common/SeverityBadge";
import type { FindingResult } from "../../types";

export function ActivityFeed({ findings }: { findings: FindingResult[] }) {
  const recent = [...findings]
    .sort((a, b) => new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime())
    .slice(0, 10);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Recent Findings</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {recent.map((f) => (
            <div key={f.finding_id} className="flex items-center justify-between text-sm">
              <div className="flex-1 truncate pr-2">{f.rule_name || f.rule_id}</div>
              <SeverityBadge severity={f.severity} />
            </div>
          ))}
          {recent.length === 0 && (
            <p className="text-sm text-[hsl(var(--muted-foreground))]">No findings yet</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
