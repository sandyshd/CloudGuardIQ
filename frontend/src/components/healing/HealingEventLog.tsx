import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Badge } from "../ui/badge";
import { History } from "lucide-react";
import type { HealingEvent } from "../../types";

export function HealingEventLog({ events }: { events: HealingEvent[] }) {
  const statusVariant = (status: string) => {
    if (status === "success") return "success" as const;
    if (status === "failure") return "destructive" as const;
    return "secondary" as const;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Healing events</CardTitle>
      </CardHeader>
      <CardContent>
        {events.length === 0 ? (
          <div className="flex items-center gap-3 rounded-md border border-dashed border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.4)] p-4 text-sm text-[hsl(var(--muted-foreground))]">
            <History className="h-4 w-4 shrink-0" />
            No healing events yet. Once the agent is enabled, remediation
            actions will appear here in chronological order.
          </div>
        ) : (
          <ul className="divide-y divide-[hsl(var(--border))]">
            {events.map((e) => (
              <li
                key={e.id}
                className="flex items-center justify-between gap-3 py-3 text-sm"
              >
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium text-[hsl(var(--foreground))]">
                    {e.action}
                  </div>
                  <p className="truncate text-xs text-[hsl(var(--muted-foreground))]">
                    {e.details}
                  </p>
                </div>
                <Badge variant={statusVariant(e.status)}>{e.status}</Badge>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
