import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { SeverityBadge } from "../common/SeverityBadge";
import type { FindingResult } from "../../types";

export function ActivityFeed({ findings }: { findings: FindingResult[] }) {
  const recent = [...findings]
    .sort(
      (a, b) =>
        new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime()
    )
    .slice(0, 5);

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">Recent Activity</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {recent.map((f, i) => (
            <div key={f.finding_id} className="flex items-start gap-3 text-sm">
              <div className="relative flex flex-col items-center">
                <div className="h-2 w-2 rounded-full bg-blue-500 mt-1.5" />
                {i < recent.length - 1 && (
                  <div className="w-px flex-1 bg-gray-200 min-h-[24px]" />
                )}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-medium">
                    {f.rule_name || f.rule_id}
                  </span>
                  <SeverityBadge severity={f.severity} />
                </div>
                <span className="text-xs text-[hsl(var(--muted-foreground))]">
                  {new Date(f.detected_at).toLocaleString()}
                </span>
              </div>
            </div>
          ))}
          {recent.length === 0 && (
            <p className="text-sm text-[hsl(var(--muted-foreground))]">
              No scan events yet
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
