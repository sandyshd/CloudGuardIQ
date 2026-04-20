import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";

export function AgentConfig() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Repair Agent Configuration</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          Configure auto-repair thresholds and approval workflows. Coming soon.
        </p>
      </CardContent>
    </Card>
  );
}
