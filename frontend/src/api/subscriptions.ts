import apiClient from "./client";
import type { Subscription } from "../types";

export async function getSubscriptions(): Promise<Subscription[]> {
  const { data } = await apiClient.get<Subscription[]>("/subscriptions");
  return data;
}

export async function addSubscription(
  subscription_id: string,
  display_name = "",
  customer_tenant_id = "",
): Promise<Subscription> {
  const body: Record<string, string> = { subscription_id, display_name };
  if (customer_tenant_id) body.customer_tenant_id = customer_tenant_id;
  const { data } = await apiClient.post<Subscription>("/subscriptions", body);
  return data;
}

export async function removeSubscription(subscription_id: string): Promise<void> {
  await apiClient.delete(`/subscriptions/${subscription_id}`);
}

export async function renameSubscription(
  subscription_id: string,
  display_name: string,
): Promise<Subscription> {
  const { data } = await apiClient.patch<Subscription>(
    `/subscriptions/${subscription_id}`,
    { display_name },
  );
  return data;
}

export async function toggleSubscription(
  subscription_id: string,
  state: "Enabled" | "Disabled",
): Promise<Subscription> {
  const { data } = await apiClient.patch<Subscription>(
    `/subscriptions/${subscription_id}`,
    { state },
  );
  return data;
}


// ---------------------------------------------------------------------------
// Cross-tenant onboarding
// ---------------------------------------------------------------------------

export interface ConsentUrlResponse {
  customer_tenant_id: string;
  consent_url: string;
}

export interface ConsentRecordResponse {
  customer_tenant_id: string;
  consented_at: string;
}

export interface OnboardingTemplateResponse {
  customer_tenant_id: string;
  azure_principal_id: string;
  template_uri: string;
  deploy_url: string;
  scope: "subscription" | "managementGroup";
}

export interface DiscoveredSubscription {
  subscription_id: string;
  display_name: string;
  state: string;
  already_linked: boolean;
}

export interface DiscoverResponse {
  customer_tenant_id: string;
  subscriptions: DiscoveredSubscription[];
}

export interface OnboardingSessionResponse {
  session_id: string;
  customer_tenant_id: string;
  status:
    | "pending_consent"
    | "pending_reader"
    | "pending_discovery"
    | "subscriptions_discovered"
    | "completed"
    | string;
  consent_url: string;
  discovered_subscription_ids: string[];
  connected_subscription_ids: string[];
}

export async function getConsentUrl(
  tenant_id: string,
  state = "",
): Promise<ConsentUrlResponse> {
  const { data } = await apiClient.get<ConsentUrlResponse>(
    "/subscriptions/consent-url",
    { params: { tenant_id, state } },
  );
  return data;
}

export async function recordConsentCallback(
  tenant: string,
  admin_consent: string,
  error?: string,
  error_description?: string,
  state?: string,
): Promise<ConsentRecordResponse> {
  const { data } = await apiClient.get<ConsentRecordResponse>(
    "/subscriptions/consent-callback",
    {
      params: {
        tenant,
        admin_consent,
        ...(error ? { error } : {}),
        ...(error_description ? { error_description } : {}),
        ...(state ? { state } : {}),
      },
    },
  );
  return data;
}

export async function getOnboardingTemplate(
  tenant_id: string,
  scope: "subscription" | "managementGroup" = "managementGroup",
): Promise<OnboardingTemplateResponse> {
  const { data } = await apiClient.get<OnboardingTemplateResponse>(
    "/subscriptions/onboarding-template",
    { params: { tenant_id, scope } },
  );
  return data;
}

export async function discoverSubscriptions(
  tenant_id: string,
): Promise<DiscoverResponse> {
  const { data } = await apiClient.get<DiscoverResponse>(
    "/subscriptions/discover",
    { params: { tenant_id } },
  );
  return data;
}

export async function createOnboardingSession(
  customer_tenant_id: string,
): Promise<OnboardingSessionResponse> {
  const { data } = await apiClient.post<OnboardingSessionResponse>(
    "/subscriptions/onboarding-sessions",
    { customer_tenant_id },
  );
  return data;
}

export async function getOnboardingSession(
  session_id: string,
): Promise<OnboardingSessionResponse> {
  const { data } = await apiClient.get<OnboardingSessionResponse>(
    `/subscriptions/onboarding-sessions/${session_id}`,
  );
  return data;
}

export async function markOnboardingReaderGranted(
  session_id: string,
): Promise<OnboardingSessionResponse> {
  const { data } = await apiClient.post<OnboardingSessionResponse>(
    `/subscriptions/onboarding-sessions/${session_id}/reader-granted`,
  );
  return data;
}

export async function discoverOnboardingSession(
  session_id: string,
): Promise<OnboardingSessionResponse> {
  const { data } = await apiClient.post<OnboardingSessionResponse>(
    `/subscriptions/onboarding-sessions/${session_id}/discover`,
  );
  return data;
}

export async function connectOnboardingSession(
  session_id: string,
  subscription_ids: string[] = [],
): Promise<OnboardingSessionResponse> {
  const { data } = await apiClient.post<OnboardingSessionResponse>(
    `/subscriptions/onboarding-sessions/${session_id}/connect`,
    { subscription_ids },
  );
  return data;
}
