import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import { SeverityBadge } from "../common/SeverityBadge";
import { DataTierBadge } from "../common/DataTierBadge";
import type { FindingResult } from "../../types";

interface FindingTableProps {
  findings: FindingResult[];
  onSelect: (finding: FindingResult) => void;
}

export function FindingTable({ findings, onSelect }: FindingTableProps) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Rule</TableHead>
          <TableHead>Resource</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Tier</TableHead>
          <TableHead>Waste/mo</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((f) => (
          <TableRow key={f.finding_id} className="cursor-pointer" onClick={() => onSelect(f)}>
            <TableCell className="font-medium">{f.rule_name || f.rule_id}</TableCell>
            <TableCell className="max-w-[200px] truncate">{f.resource_snapshot?.resource_name || "—"}</TableCell>
            <TableCell><SeverityBadge severity={f.severity} /></TableCell>
            <TableCell className="text-xs">{f.finding_type}</TableCell>
            <TableCell>{f.resource_snapshot?.data_tier ? <DataTierBadge tier={f.resource_snapshot.data_tier} /> : "—"}</TableCell>
            <TableCell>{f.waste_monthly_usd > 0 ? `$${f.waste_monthly_usd.toFixed(2)}` : "—"}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
