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
import { Badge } from "../ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Search, ChevronRight } from "lucide-react";
import type { FindingResult, Severity } from "../../types";
import type { FrameworkScore } from "../../api/compliance";

interface ControlListProps {
  findings: FindingResult[];
  framework: string | null;
  onFrameworkChange: (framework: string | null) => void;
  onSelect?: (finding: FindingResult) => void;
  /** Scorecard rows from the compliance API. When provided, framework
   * filtering matches by the backend-supplied tag prefixes so a family
   * selection (``CIS_AZURE``) correctly maps to granular tags
   * (``CIS_1.5``). When absent we fall back to equality / ``id_`` prefix. */
  scorecard?: FrameworkScore[];
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
  scorecard,
}: ControlListProps) {
  const [severity, setSeverity] = useState<Severity | "ALL">("ALL");
  const [search, setSearch] = useState("");

  // The "Failed controls" card mirrors the backend definition of failing:
  // status === OPEN. Including APPLIED / SNOOZED / RESOLVED here would
  // make the table disagree with the scorecard's open-finding counts.
  const compliance = useMemo(
    () =>
      findings.filter(
        (f) => f.compliance_frameworks.length > 0 && f.status === "OPEN",
      ),
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
    // ``framework`` may be a granular tag (``SOC2_CC6.1``) from the
    // dropdown, or a family id (``CIS_AZURE``, ``NIST_800_53`` …) from a
    // row click. Resolve via the scorecard's authoritative prefix list
    // when available. The static fallback below keeps filtering correct
    // even before the API redeploys with the ``prefixes`` field.
    const FALLBACK_PREFIXES: Record<string, string[]> = {
      CIS_AZURE: ["CIS_"],
      NIST_800_53: ["NIST_"],
      ISO_27001: ["ISO_27001_", "ISO27001_", "ISO_"],
      PCI_DSS: ["PCI_DSS_", "PCI_", "PCIDSS_"],
      SOC2: ["SOC2_", "SOC_2_"],
      HIPAA: ["HIPAA_"],
    };
    const matchesFramework = (tags: string[]): boolean => {
      if (!framework) return true;
      const row = scorecard?.find((r) => r.framework_id === framework);
      const prefixes =
        row?.prefixes && row.prefixes.length > 0
          ? row.prefixes
          : (FALLBACK_PREFIXES[framework] ?? [`${framework}_`]);
      return tags.some(
        (fw) =>
          fw === framework || prefixes.some((p) => fw.startsWith(p)),
      );
    };
    return compliance
      .filter((f) => matchesFramework(f.compliance_frameworks))
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

  const inputClass =
    "h-9 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))] focus-visible:border-[hsl(var(--ring))]";

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle>Failed controls</CardTitle>
          <span className="text-xs text-[hsl(var(--muted-foreground))]">
            Showing {rows.length} of {compliance.length}
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search control or resource…"
              className={`${inputClass} pl-8`}
            />
          </div>
          <select
            className={inputClass}
            value={framework ?? "ALL"}
            onChange={(e) =>
              onFrameworkChange(e.target.value === "ALL" ? null : e.target.value)
            }
          >
            <option value="ALL">All frameworks</option>
            {frameworks.map((fw) => (
              <option key={fw} value={fw}>
                {fw}
              </option>
            ))}
          </select>
          <select
            className={inputClass}
            value={severity}
            onChange={(e) =>
              setSeverity(e.target.value as Severity | "ALL")
            }
          >
            <option value="ALL">All severities</option>
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
          <div className="rounded-[var(--radius)] border border-dashed border-[hsl(var(--border))] p-8 text-center text-sm text-[hsl(var(--muted-foreground))]">
            No controls match the current filters.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-[var(--radius)] border border-[hsl(var(--border))]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Control</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Frameworks</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-8" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((f) => (
                  <TableRow
                    key={f.finding_id}
                    onClick={() => onSelect?.(f)}
                    className={onSelect ? "group cursor-pointer" : undefined}
                  >
                    <TableCell className="max-w-[280px]">
                      <div className="truncate text-[13px] font-medium text-[hsl(var(--foreground))]">
                        {f.rule_name || f.rule_id}
                      </div>
                      <div className="truncate font-mono text-[11px] text-[hsl(var(--muted-foreground))]">
                        {f.rule_id}
                      </div>
                    </TableCell>
                    <TableCell className="max-w-[240px]">
                      <div className="truncate text-sm text-[hsl(var(--foreground))]">
                        {f.resource_snapshot?.resource_name || "—"}
                      </div>
                      <div className="truncate font-mono text-[11px] text-[hsl(var(--muted-foreground))]">
                        {f.resource_snapshot?.resource_type
                          ?.split("/")
                          .pop() || ""}
                      </div>
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={f.severity} />
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {f.compliance_frameworks.map((fw) => (
                          <Badge key={fw} variant="outline">
                            {fw}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          f.status === "RESOLVED"
                            ? "success"
                            : f.status === "OPEN"
                              ? "warning"
                              : "secondary"
                        }
                      >
                        {f.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="w-8">
                      {onSelect && (
                        <ChevronRight className="h-4 w-4 text-[hsl(var(--muted-foreground))] opacity-0 transition-all group-hover:translate-x-0.5 group-hover:opacity-100" />
                      )}
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
