import { useEffect, useRef, useState } from "react";
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
import { SourceBadge } from "../common/SourceBadge";
import { Badge } from "../ui/badge";
import { ChevronRight, Copy, Check } from "lucide-react";
import { cn } from "../../lib/utils";
import type { FindingResult, Severity, FindingStatus } from "../../types";

interface FindingTableProps {
  findings: FindingResult[];
  onSelect: (finding: FindingResult) => void;
}

const severityRail: Record<Severity, string> = {
  CRITICAL: "bg-[hsl(var(--severity-critical))]",
  HIGH: "bg-[hsl(var(--severity-high))]",
  MEDIUM: "bg-[hsl(var(--severity-medium))]",
  LOW: "bg-[hsl(var(--severity-low))]",
  INFORMATIONAL: "bg-[hsl(var(--severity-info))]",
};

const statusVariant: Record<FindingStatus, "secondary" | "success" | "warning" | "default"> = {
  OPEN: "warning",
  RESOLVED: "success",
  SNOOZED: "secondary",
  APPLIED: "default",
};

function ResourceIdMono({ id, name }: { id?: string; name: string }) {
  const [copied, setCopied] = useState(false);
  if (!id) return <span className="font-medium text-[hsl(var(--foreground))]">{name}</span>;
  const onCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(id);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <div className="flex flex-col gap-0.5 min-w-0">
      <span className="truncate font-medium text-[hsl(var(--foreground))]">{name}</span>
      <span className="flex items-center gap-1.5 text-[11px] text-[hsl(var(--muted-foreground))]">
        <code className="truncate font-mono">{id.split("/").slice(-2).join("/")}</code>
        <button
          type="button"
          onClick={onCopy}
          aria-label="Copy resource id"
          className="cgq-no-touch-target rounded p-0.5 text-[hsl(var(--muted-foreground))] transition-colors hover:bg-[hsl(var(--muted))] hover:text-[hsl(var(--foreground))]"
          title={id}
        >
          {copied ? <Check className="h-3 w-3 text-[hsl(var(--success))]" /> : <Copy className="h-3 w-3" />}
        </button>
      </span>
    </div>
  );
}

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  return target.isContentEditable;
}

function resolveMonthlyImpact(finding: FindingResult): { amount: number; estimated: boolean } {
  const direct = Math.max(finding.direct_waste_monthly_usd ?? finding.waste_monthly_usd ?? 0, 0);
  const estimated = Math.max(finding.estimated_impact_monthly_usd ?? 0, 0);
  const amount = Math.max(direct, estimated, 0);
  return {
    amount,
    estimated: amount > 0 && direct <= 0 && estimated > 0,
  };
}

export function FindingTable({ findings, onSelect }: FindingTableProps) {
  const [active, setActive] = useState(0);
  const rowRefs = useRef<Array<HTMLTableRowElement | null>>([]);

  useEffect(() => {
    setActive((a) => Math.min(a, Math.max(findings.length - 1, 0)));
  }, [findings.length]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (isTypingTarget(e.target) || e.metaKey || e.ctrlKey || e.altKey) return;
      if (findings.length === 0) return;
      const key = e.key.toLowerCase();
      if (key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        setActive((a) => Math.min(a + 1, findings.length - 1));
      } else if (key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        setActive((a) => Math.max(a - 1, 0));
      } else if (e.key === "Enter") {
        const f = findings[active];
        if (f) {
          e.preventDefault();
          onSelect(f);
        }
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [findings, active, onSelect]);

  useEffect(() => {
    const el = rowRefs.current[active];
    el?.scrollIntoView({ block: "nearest" });
  }, [active]);

  if (findings.length === 0) {
    return (
      <div className="overflow-hidden rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))]">
        <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
          <div className="text-sm font-medium text-[hsl(var(--foreground))]">No findings match these filters</div>
          <div className="mt-1 text-xs text-[hsl(var(--muted-foreground))]">
            Try clearing severity, type, or status filters above.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))]">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[1px] p-0" aria-hidden />
            <TableHead className="min-w-[220px]">Resource</TableHead>
            <TableHead className="min-w-[260px]">Finding</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Tier</TableHead>
            <TableHead className="text-right">Waste / mo</TableHead>
            <TableHead className="text-right">Priority</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="w-8" aria-label="Open" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {findings.map((f, idx) => {
            const status = (f.status ?? "OPEN") as FindingStatus;
            const isActive = idx === active;
            return (
              <TableRow
                key={f.finding_id}
                ref={(el) => {
                  rowRefs.current[idx] = el;
                }}
                data-active={isActive ? "true" : undefined}
                aria-selected={isActive}
                className="group cursor-pointer"
                onClick={() => {
                  setActive(idx);
                  onSelect(f);
                }}
                onMouseEnter={() => setActive(idx)}
              >
                <TableCell className="w-[3px] p-0">
                  <span
                    className={cn(
                      "block h-full min-h-[44px] w-[3px]",
                      severityRail[f.severity],
                    )}
                    aria-hidden
                  />
                </TableCell>
                <TableCell className="max-w-[260px]">
                  <ResourceIdMono
                    id={f.resource_snapshot?.id}
                    name={f.resource_snapshot?.resource_name || "—"}
                  />
                </TableCell>
                <TableCell className="max-w-[360px]">
                  <div className="flex items-center gap-1.5">
                    <span className="truncate text-[13px] font-medium text-[hsl(var(--foreground))]">
                      {f.rule_name || f.rule_id}
                    </span>
                    <SourceBadge ruleId={f.rule_id} />
                  </div>
                  <div className="truncate text-xs text-[hsl(var(--muted-foreground))]">
                    {f.description}
                  </div>
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
                    <span className="text-xs text-[hsl(var(--muted-foreground))]">—</span>
                  )}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {(() => {
                    const impact = resolveMonthlyImpact(f);
                    if (impact.amount <= 0) {
                      return <span className="text-xs text-[hsl(var(--muted-foreground))]">—</span>;
                    }
                    return (
                      <div className="inline-flex items-center gap-1.5">
                        <span className="font-medium text-[hsl(var(--severity-critical))]">
                          ${impact.amount.toFixed(2)}
                        </span>
                        {impact.estimated ? (
                          <span className="rounded bg-[hsl(var(--muted))] px-1 py-0.5 text-[10px] uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
                            est.
                          </span>
                        ) : null}
                      </div>
                    );
                  })()}
                </TableCell>
                <TableCell className="text-right font-mono text-xs tabular-nums text-[hsl(var(--muted-foreground))]">
                  {f.priority_score}
                </TableCell>
                <TableCell>
                  <Badge variant={statusVariant[status]}>{status}</Badge>
                </TableCell>
                <TableCell>
                  <ChevronRight className="h-4 w-4 text-[hsl(var(--muted-foreground))] transition-transform group-hover:translate-x-0.5 group-hover:text-[hsl(var(--foreground))]" />
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

