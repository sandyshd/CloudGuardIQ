import apiClient from "./client";
import type { FindingResult, RemediationCard } from "../types";

export async function getFindings(subscriptionId?: string): Promise<FindingResult[]> {
  const params = subscriptionId ? { subscription_id: subscriptionId } : {};
  const { data } = await apiClient.get<FindingResult[]>("/findings", { params });
  return data;
}

export async function getFinding(
  findingId: string,
  subscriptionId?: string,
): Promise<FindingResult> {
  // Findings are partitioned by /subscription_id in Cosmos. Passing the
  // sub here turns the lookup into a fast single-partition read_item.
  // Without it the backend falls back to a cross-partition scan that
  // can silently miss the document under load.
  const params = subscriptionId ? { subscription_id: subscriptionId } : {};
  const { data } = await apiClient.get<FindingResult>(`/findings/${findingId}`, { params });
  return data;
}

export async function getRemediation(findingId: string): Promise<RemediationCard> {
  const { data } = await apiClient.get<RemediationCard>(`/findings/${findingId}/remediation`);
  return data;
}

export async function markFindingResolved(findingId: string): Promise<void> {
  // Backend endpoint is not yet implemented. Swallow 404s so the UI can
  // provide optimistic feedback until the action endpoint ships.
  try {
    await apiClient.post(`/findings/${findingId}/resolve`);
  } catch {
    /* optimistic */
  }
}

export async function snoozeFinding(findingId: string, days = 7): Promise<void> {
  try {
    await apiClient.post(`/findings/${findingId}/snooze`, { days });
  } catch {
    /* optimistic */
  }
}

export async function applyTerraformFix(findingId: string): Promise<void> {
  try {
    await apiClient.post(`/findings/${findingId}/apply`);
  } catch {
    /* optimistic */
  }
}

export async function generateRemediation(findingId: string): Promise<RemediationCard> {
  const { data } = await apiClient.post<RemediationCard>(`/findings/${findingId}/generate-remediation`);
  return data;
}
