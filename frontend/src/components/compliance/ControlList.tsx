import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import { SeverityBadge } from "../common/SeverityBadge";
import type { FindingResult } from "../../types";

export function ControlList({ findings }: { findings: FindingResult[] }) {
  const compliance = findings.filter((f) => f.compliance_frameworks.length > 0);

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Control</TableHead>
          <TableHead>Resource</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Frameworks</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {compliance.map((f) => (
          <TableRow key={f.finding_id}>
            <TableCell className="font-medium">{f.rule_name || f.rule_id}</TableCell>
            <TableCell className="truncate max-w-[200px]">{f.resource_snapshot?.resource_name || "—"}</TableCell>
            <TableCell><SeverityBadge severity={f.severity} /></TableCell>
            <TableCell className="text-xs">{f.compliance_frameworks.join(", ")}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
