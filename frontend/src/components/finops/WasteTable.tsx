import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import { SeverityBadge } from "../common/SeverityBadge";
import type { FindingResult } from "../../types";

export function WasteTable({ findings }: { findings: FindingResult[] }) {
  const finops = findings
    .filter((f) => f.finding_type === "FINOPS")
    .sort((a, b) => b.waste_monthly_usd - a.waste_monthly_usd);

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Rule</TableHead>
          <TableHead>Resource</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead className="text-right">Waste/mo</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {finops.map((f) => (
          <TableRow key={f.finding_id}>
            <TableCell className="font-medium">{f.rule_name || f.rule_id}</TableCell>
            <TableCell className="max-w-[200px] truncate">{f.resource_snapshot?.resource_name || "Unknown"}</TableCell>
            <TableCell><SeverityBadge severity={f.severity} /></TableCell>
            <TableCell className="text-right font-mono">${f.waste_monthly_usd.toFixed(2)}</TableCell>
          </TableRow>
        ))}
        {finops.length === 0 && (
          <TableRow>
            <TableCell colSpan={4} className="text-center text-[hsl(var(--muted-foreground))]">No FinOps findings</TableCell>
          </TableRow>
        )}
      </TableBody>
    </Table>
  );
}
