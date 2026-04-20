import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Badge } from "../ui/badge";
import type { HealingEvent } from "../../types";

export function HealingEventLog({ events }: { events: HealingEvent[] }) {
  const statusVariant = (status: string) => {
    if (status === "success") return "default" as const;
    if (status === "failure") return "destructive" as const;
    return "secondary" as const;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Healing Events</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {events.map((e) => (
            <div key={e.id} className="flex items-center justify-between text-sm">
              <div>
                <span className="font-medium">{e.action}</span>
                <p className="text-xs text-[hsl(var(--muted-foreground))]">{e.details}</p>
              </div>
              <Badge variant={statusVariant(e.status)}>{e.status}</Badge>
            </div>
          ))}
          {events.length === 0 && <p className="text-sm text-[hsl(var(--muted-foreground))]">No healing events</p>}
        </div>
      </CardContent>
    </Card>
  );
}
