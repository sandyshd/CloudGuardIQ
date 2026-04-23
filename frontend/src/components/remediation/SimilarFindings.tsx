import { Link } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { SeverityBadge } from "../common/SeverityBadge";
import type { FindingResult } from "../../types";

export interface SimilarFindingsProps {
  findings: FindingResult[];
}

export function SimilarFindings({ findings }: SimilarFindingsProps) {
  if (findings.length === 0) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Similar Open Findings</CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="space-y-2">
          {findings.slice(0, 3).map((f) => (
            <li key={f.finding_id}>
              <Link
                to={`/findings/${f.finding_id}`}
                className="flex items-center justify-between gap-3 rounded-md border px-3 py-2 text-sm hover:bg-[hsl(var(--muted))]"
              >
                <div className="min-w-0">
                  <div className="truncate font-medium">
                    {f.rule_name || f.rule_id}
                  </div>
                  <div className="truncate text-xs text-[hsl(var(--muted-foreground))]">
                    {f.resource_snapshot?.resource_name ?? "resource"}
                  </div>
                </div>
                <SeverityBadge severity={f.severity} />
              </Link>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
