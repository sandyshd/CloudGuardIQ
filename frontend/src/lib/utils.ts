import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { FindingResult, FindingStatus } from "../types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Statuses that explicitly take a finding out of the OPEN bucket. Anything
// else (undefined, null, unknown string, legacy casing) is treated as OPEN
// so the dashboard never silently zeros out when Cosmos returns rows
// without an explicit status field.
const CLOSED_STATUSES: ReadonlySet<string> = new Set([
  "RESOLVED",
  "SNOOZED",
  "APPLIED",
]);

export function isOpenFinding(f: Pick<FindingResult, "status">): boolean {
  const raw = f.status ?? "OPEN";
  return !CLOSED_STATUSES.has(String(raw).toUpperCase());
}

export function effectiveStatus(
  f: Pick<FindingResult, "status">,
): FindingStatus {
  const raw = String(f.status ?? "OPEN").toUpperCase();
  if (raw === "RESOLVED" || raw === "SNOOZED" || raw === "APPLIED") {
    return raw;
  }
  return "OPEN";
}