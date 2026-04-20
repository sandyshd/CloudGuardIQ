import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";

export function ReportHistory() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Report History</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">No reports generated yet.</p>
      </CardContent>
    </Card>
  );
}
