import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Badge } from "../ui/badge";

export function MonitorStatus({ active }: { active: boolean }) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">Contract Monitor</CardTitle>
        <Badge variant={active ? "default" : "secondary"}>{active ? "Active" : "Inactive"}</Badge>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          Monitors infrastructure drift and triggers self-healing when contract violations are detected.
        </p>
      </CardContent>
    </Card>
  );
}
