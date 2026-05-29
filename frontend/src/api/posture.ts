import apiClient from "./client";

export interface PostureScore {
  score: number;
  grade: string;
  rules_evaluated: number;
  rules_passed: number;
  rules_failed: number;
  weighted_total: number;
  weighted_passed: number;
  methodology: string;
}

export async function getPostureScore(
  subscriptionId?: string,
  range?: { from?: string; to?: string },
): Promise<PostureScore> {
  const params: Record<string, string> = {};
  if (subscriptionId) params.subscription_id = subscriptionId;
  if (range?.from) params.from_date = range.from;
  if (range?.to) params.to_date = range.to;
  const { data } = await apiClient.get<PostureScore>("/posture/score", { params });
  return data;
}
