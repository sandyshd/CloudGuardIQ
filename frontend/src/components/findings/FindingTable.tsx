import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../ui/table";
import { SeverityBadge } from "../common/SeverityBadge";
import { DataTierBadge } from "../common/DataTierBadge";
import { Badge } from "../ui/badge";
import { ChevronRight } from "lucide-react";
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
          <TableHead>Resource</TableHead>
          <TableHead>Description</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Tier</TableHead>
          <TableHead>Waste/mo</TableHead>
          <TableHead>Priority</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="w-8" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((f) => (
          <TableRow
            key={f.finding_id}
            className="cursor-pointer hover:bg-[hsl(var(--muted))]"
            onClick={() => onSelect(f)}
          >
            <TableCell className="font-medium max-w-[160px] truncate">
              {f.resource_snapshot?.resource_name || "\u2014"}
            </TableCell>
            <TableCell className="max-w-[240px] truncate text-sm">
              {f.description}
            </TableCell>
            <TableCell>
              <SeverityBadge severity={f.severity} />
            </TableCell>
            <TableCell>
              <Badge variant="outline">{f.finding_type}</Badge>
            </TableCell>
            <TableCell>
              {f.resource_snapshot?.data_tier ? (
                <DataTierBadge tier={f.resource_snapshot.data_tier} />
              ) : (
                "\u2014"
              )}
            </TableCell>
            <TableCell>
              {f.waste_monthly_usd > 0 ? (
                <span className="text-red-600 font-medium">
                  ${f.waste_monthly_usd.toFixed(2)}
                </span>
              ) : (
                "\u2014"
              )}
            </TableCell>
            <TableCell className="font-mono text-sm">
              {f.priority_score}
            </TableCell>
            <TableCell>
              <Badge variant="secondary">{f.status ?? "OPEN"}</Badge>
            </TableCell>
            <TableCell>
              <ChevronRight className="h-4 w-4 text-[hsl(var(--muted-foreground))]" />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}