import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Wand2 } from "lucide-react";
import { Badge } from "../ui/badge";

export function LifecycleGenerator() {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Lifecycle policy generator</CardTitle>
          <Badge variant="outline">Coming soon</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-start gap-3 rounded-md border border-dashed border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.4)] p-4">
          <Wand2 className="h-5 w-5 shrink-0 text-[hsl(var(--primary))]" />
          <p className="text-sm text-[hsl(var(--muted-foreground))]">
            Auto-generate Storage Account lifecycle rules and Cosmos throughput
            schedules from observed access patterns. Available in the next
            release.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
