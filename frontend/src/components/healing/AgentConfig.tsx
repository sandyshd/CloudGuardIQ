import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Badge } from "../ui/badge";
import { Wrench } from "lucide-react";

export function AgentConfig() {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Repair agent configuration</CardTitle>
          <Badge variant="outline">Coming soon</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-start gap-3 rounded-md border border-dashed border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.4)] p-4">
          <Wrench className="h-5 w-5 shrink-0 text-[hsl(var(--primary))]" />
          <p className="text-sm text-[hsl(var(--muted-foreground))]">
            Configure auto-repair thresholds, approval workflows, and rollback
            windows. Available in the next release.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
