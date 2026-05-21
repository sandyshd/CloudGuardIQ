import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Activity } from "lucide-react";
import { cn } from "../../lib/utils";

export function MonitorStatus({ active }: { active: boolean }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Contract monitor</CardTitle>
          <span
            className={cn(
              "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide",
              active
                ? "bg-[hsl(var(--success)/0.14)] text-[hsl(var(--success))]"
                : "bg-[hsl(var(--muted))] text-[hsl(var(--muted-foreground))]",
            )}
          >
            <span
              className={cn(
                "h-1.5 w-1.5 rounded-full",
                active
                  ? "bg-[hsl(var(--success))] animate-pulse"
                  : "bg-[hsl(var(--muted-foreground))]",
              )}
            />
            {active ? "Active" : "Inactive"}
          </span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-start gap-3">
          <Activity className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--primary))]" />
          <p className="text-sm text-[hsl(var(--muted-foreground))]">
            Watches infrastructure for drift and triggers self-healing flows
            when contract violations are detected. Enable from the agent
            configuration panel.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
