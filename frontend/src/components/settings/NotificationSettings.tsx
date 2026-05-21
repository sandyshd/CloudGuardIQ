import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Badge } from "../ui/badge";
import { Bell } from "lucide-react";

export function NotificationSettings() {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Notifications</CardTitle>
          <Badge variant="outline">Coming soon</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-start gap-3 rounded-md border border-dashed border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.4)] p-4">
          <Bell className="h-5 w-5 shrink-0 text-[hsl(var(--primary))]" />
          <p className="text-sm text-[hsl(var(--muted-foreground))]">
            Email and Microsoft Teams alerts for new critical findings,
            compliance drift, and applied remediations.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
