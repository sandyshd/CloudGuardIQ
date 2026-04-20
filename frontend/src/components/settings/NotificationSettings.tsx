import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";

export function NotificationSettings() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Notifications</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          Configure email and Teams notifications for new findings. Coming soon.
        </p>
      </CardContent>
    </Card>
  );
}
