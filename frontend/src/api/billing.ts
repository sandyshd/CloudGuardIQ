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

/**
 * Directly switch to any plan without a Stripe checkout.
 * Used while billing is in Stripe-free mode (backend POST /billing/select).
 */
export async function selectTier(tier: BillingTier): Promise<BillingStatus> {
  const { data } = await apiClient.post<BillingStatus>("/billing/select", { tier });
  return data;
}

export async function downgradeTier(tier: BillingTier): Promise<BillingStatus> {
  const { data } = await apiClient.post<BillingStatus>("/billing/downgrade", { tier });
  return data;
}
