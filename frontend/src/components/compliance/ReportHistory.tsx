import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { FileText } from "lucide-react";

export function ReportHistory() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Report history</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-3 rounded-md border border-dashed border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.4)] p-4 text-sm text-[hsl(var(--muted-foreground))]">
          <FileText className="h-4 w-4 shrink-0" />
          No reports generated yet. Exporting compliance reports as PDF will appear here.
        </div>
      </CardContent>
    </Card>
  );
}
