import apiClient from "./client";

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface FrameworkScore {
  framework_id: string;
  label: string;
  short_label: string;
  /** Tag prefixes used by the backend to route findings to this row.
   * Used to filter findings client-side without duplicating the table. */
  prefixes?: string[];
  controls_total: number;
  controls_failed: number;
  controls_passed: number;
  score: number;
  open_findings: number;
  severity_breakdown: SeverityBreakdown;
}

export async function getComplianceScorecard(
  subscriptionId?: string,
  range?: { from?: string; to?: string },
): Promise<FrameworkScore[]> {
  const params: Record<string, string> = {};
  if (subscriptionId) params.subscription_id = subscriptionId;
  if (range?.from) params.from_date = range.from;
  if (range?.to) params.to_date = range.to;
  const { data } = await apiClient.get<FrameworkScore[]>("/compliance/scorecard", { params });
  return data;
}
