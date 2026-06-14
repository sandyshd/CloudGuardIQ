import apiClient from "./client";
import type { ResourceSnapshot } from "../types";

export async function getResources(
  subscriptionId?: string,
  limit = 1000,
): Promise<ResourceSnapshot[]> {
  const params: Record<string, string | number> = { limit };
  if (subscriptionId) params.subscription_id = subscriptionId;
  const { data } = await apiClient.get<ResourceSnapshot[]>("/resources", { params });
  return data;
}
