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
): Promise<PostureScore> {
  const params = subscriptionId ? { subscription_id: subscriptionId } : undefined;
  const { data } = await apiClient.get<PostureScore>("/posture/score", { params });
  return data;
}
