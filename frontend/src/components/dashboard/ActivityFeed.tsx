import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { SeverityBadge } from "../common/SeverityBadge";
import type { FindingResult } from "../../types";

function relativeTime(iso: string): string {
  const date = new Date(iso);
  const diff = Date.now() - date.getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d ago`;
  return date.toLocaleDateString();
}

export function ActivityFeed({ findings }: { findings: FindingResult[] }) {
  const recent = [...findings]
    .sort(
      (a, b) =>
        new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime(),
    )
    .slice(0, 6);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent activity</CardTitle>
      </CardHeader>
      <CardContent>
        {recent.length === 0 ? (
          <p className="text-sm text-[hsl(var(--muted-foreground))]">
            No scan events yet.
          </p>
        ) : (
          <ul className="space-y-3">
            {recent.map((f, i) => (
              <li key={f.finding_id} className="flex items-start gap-3 text-sm">
                <div className="relative flex flex-col items-center">
                  <span className="mt-1.5 h-2 w-2 rounded-full bg-[hsl(var(--primary))]" />
                  {i < recent.length - 1 && (
                    <span className="min-h-[28px] w-px flex-1 bg-[hsl(var(--border))]" />
                  )}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-medium text-[hsl(var(--foreground))]">
                      {f.rule_name || f.rule_id}
                    </span>
                    <SeverityBadge severity={f.severity} />
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-xs text-[hsl(var(--muted-foreground))]">
                    <span>{relativeTime(f.detected_at)}</span>
                    {f.resource_snapshot?.resource_name && (
                      <>
                        <span>·</span>
                        <span className="truncate">
                          {f.resource_snapshot.resource_name}
                        </span>
                      </>
                    )}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
