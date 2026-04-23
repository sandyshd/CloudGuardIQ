import apiClient from "./client";

export type BillingTier = "FREE" | "PRO" | "ENTERPRISE";

export interface BillingStatus {
  tier: BillingTier;
  stripe_customer_id: string;
  stripe_subscription_id: string;
}

export async function getBillingStatus(): Promise<BillingStatus> {
  const { data } = await apiClient.get<BillingStatus>("/billing/status");
  return data;
}

export async function createCheckout(tier: BillingTier): Promise<string> {
  const { data } = await apiClient.post<{ url: string }>("/billing/checkout", { tier });
  return data.url;
}
