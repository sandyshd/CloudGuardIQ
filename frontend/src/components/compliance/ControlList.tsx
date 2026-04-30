import { useMemo, useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../ui/table";
import { SeverityBadge } from "../common/SeverityBadge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Search } from "lucide-react";
import type { FindingResult, Severity } from "../../types";

interface ControlListProps {
  findings: FindingResult[];
  framework: string | null;
  onFrameworkChange: (framework: string | null) => void;
  onSelect?: (finding: FindingResult) => void;
}

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFORMATIONAL: 0,
};

export function ControlList({
  findings,
  framework,
  onFrameworkChange,
  onSelect,
}: ControlListProps) {
  const [severity, setSeverity] = useState<Severity | "ALL">("ALL");
  const [search, setSearch] = useState("");

  const compliance = useMemo(
    () => findings.filter((f) => f.compliance_frameworks.length > 0),
    [findings],
  );

  const frameworks = useMemo(() => {
    const set = new Set<string>();
    compliance.forEach((f) =>
      f.compliance_frameworks.forEach((fw) => set.add(fw)),
    );
    return [...set].sort();
  }, [compliance]);

  const rows = useMemo(() => {
    const term = search.trim().toLowerCase();
    return compliance
      .filter((f) =>
        framework ? f.compliance_frameworks.includes(framework) : true,
      )
      .filter((f) => (severity === "ALL" ? true : f.severity === severity))
      .filter((f) => {
        if (!term) return true;
        const hay = [
          f.rule_name,
          f.rule_id,
          f.resource_snapshot?.resource_name,
          f.resource_snapshot?.resource_type,
          ...(f.compliance_frameworks ?? []),
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return hay.includes(term);
      })
      .sort(
        (a, b) =>
          SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
          b.priority_score - a.priority_score,
      );
  }, [compliance, framework, severity, search]);

  const filtersActive =
    framework !== null || severity !== "ALL" || search.trim().length > 0;

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle className="text-base">Failed Controls</CardTitle>
          <span className="text-xs text-[hsl(var(--muted-foreground))]">
            Showing {rows.length} of {compliance.length}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search control or resource..."
              className="rounded border bg-[hsl(var(--background))] py-2 pl-8 pr-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <select
            className="rounded border bg-[hsl(var(--background))] px-3 py-2 text-sm"
            value={framework ?? "ALL"}
            onChange={(e) =>
              onFrameworkChange(e.target.value === "ALL" ? null : e.target.value)
            }
          >
            <option value="ALL">All Frameworks</option>
            {frameworks.map((fw) => (
              <option key={fw} value={fw}>
                {fw}
              </option>
            ))}
          </select>
          <select
            className="rounded border bg-[hsl(var(--background))] px-3 py-2 text-sm"
            value={severity}
            onChange={(e) =>
              setSeverity(e.target.value as Severity | "ALL")
            }
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFORMATIONAL">Informational</option>
          </select>
          {filtersActive && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setSeverity("ALL");
                setSearch("");
                onFrameworkChange(null);
              }}
            >
              Clear filters
            </Button>
          )}
        </div>

        {rows.length === 0 ? (
          <div className="rounded-lg border border-dashed p-8 text-center text-sm text-[hsl(var(--muted-foreground))]">
            No controls match the current filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Control</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Frameworks</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((f) => (
                  <TableRow
                    key={f.finding_id}
                    onClick={() => onSelect?.(f)}
                    className={onSelect ? "cursor-pointer hover:bg-[hsl(var(--muted))]" : undefined}
                  >
                    <TableCell className="font-medium">
                      <div className="text-sm">{f.rule_name || f.rule_id}</div>
                      <div className="text-xs text-[hsl(var(--muted-foreground))]">
                        {f.rule_id}
                      </div>
                    </TableCell>
                    <TableCell className="max-w-[240px] truncate">
                      <div className="text-sm">
                        {f.resource_snapshot?.resource_name || "—"}
                      </div>
                      <div className="text-xs text-[hsl(var(--muted-foreground))]">
                        {f.resource_snapshot?.resource_type
                          ?.split("/")
                          .pop() || ""}
                      </div>
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={f.severity} />
                    </TableCell>
                    <TableCell className="text-xs">
                      <div className="flex flex-wrap gap-1">
                        {f.compliance_frameworks.map((fw) => (
                          <span
                            key={fw}
                            className="rounded-full border px-2 py-0.5"
                          >
                            {fw}
                          </span>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs uppercase text-[hsl(var(--muted-foreground))]">
                      {f.status}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
