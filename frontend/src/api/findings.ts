import apiClient from "./client";
import type { FindingResult, RemediationCard } from "../types";

export async function getFindings(subscriptionId?: string): Promise<FindingResult[]> {
  const params = subscriptionId ? { subscription_id: subscriptionId } : {};
  const { data } = await apiClient.get<FindingResult[]>("/findings", { params });
  return data;
}

export async function getFinding(findingId: string): Promise<FindingResult> {
  const { data } = await apiClient.get<FindingResult>(`/findings/${findingId}`);
  return data;
}

export async function getRemediation(findingId: string): Promise<RemediationCard> {
  const { data } = await apiClient.get<RemediationCard>(`/findings/${findingId}/remediation`);
  return data;
}
