import apiClient from "./client";
import type { FindingResult, RemediationCard } from "../types";

export interface DateRangeParams {
  from?: string;
  to?: string;
}

export async function getFindings(
  subscriptionId?: string,
  limit = 5000,
  range?: DateRangeParams,
): Promise<FindingResult[]> {
  const params: Record<string, string | number> = { limit };
  if (subscriptionId) params.subscription_id = subscriptionId;
  if (range?.from) params.from_date = range.from;
  if (range?.to) params.to_date = range.to;
  const { data } = await apiClient.get<FindingResult[]>("/findings", { params });
  return data;
}

export async function getFinding(
  findingId: string,
  subscriptionId?: string,
): Promise<FindingResult> {
  // Findings are partitioned by /subscription_id in Cosmos. Passing the
  // sub here turns the lookup into a fast single-partition read_item.
  const params = subscriptionId ? { subscription_id: subscriptionId } : undefined;
  const { data } = await apiClient.get<FindingResult>(`/findings/${findingId}`, { params });
  return data;
}

export async function getRemediation(findingId: string): Promise<RemediationCard> {
  const { data } = await apiClient.get<RemediationCard>(`/findings/${findingId}/remediation`);
  return data;
}

export async function markFindingResolved(
  findingId: string,
  subscriptionId: string,
): Promise<FindingResult> {
  const { data } = await apiClient.post<FindingResult>(
    `/findings/${findingId}/resolve`,
    { subscription_id: subscriptionId },
  );
  return data;
}

export async function snoozeFinding(
  findingId: string,
  subscriptionId: string,
  days = 7,
): Promise<FindingResult> {
  const { data } = await apiClient.post<FindingResult>(
    `/findings/${findingId}/snooze`,
    { subscription_id: subscriptionId, days },
  );
  return data;
}

export async function applyTerraformFix(
  findingId: string,
  subscriptionId: string,
): Promise<FindingResult> {
  const { data } = await apiClient.post<FindingResult>(
    `/findings/${findingId}/apply`,
    { subscription_id: subscriptionId },
  );
  return data;
}

export async function generateRemediation(findingId: string): Promise<RemediationCard> {
  const { data } = await apiClient.post<RemediationCard>(`/findings/${findingId}/generate-remediation`);
  return data;
}

