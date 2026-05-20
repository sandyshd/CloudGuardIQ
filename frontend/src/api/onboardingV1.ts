import apiClient from "./client";

export type CloudProvider = "AZURE" | "AWS" | "GCP";

export interface OnboardingTargetScope {
  tenant_id?: string;
  account_id?: string;
  project_id?: string;
  organization_id?: string;
}

export interface OnboardingSessionCreateRequestV1 {
  provider: CloudProvider;
  display_name: string;
  target_scope: OnboardingTargetScope;
}

export interface VerificationCheck {
  check: string;
  status: string;
}

export interface DiscoveredScope {
  id: string;
  display_name: string;
  kind: string;
}

export interface OnboardingSessionResponseV1 {
  session_id: string;
  provider: CloudProvider;
  customer_tenant_id: string;
  status: string;
  next_actions: string[];
  artifacts: Record<string, string>;
  discovered_scopes: DiscoveredScope[];
  linked_scope_ids: string[];
  verification_checks: VerificationCheck[];
  connection_id: string;
}

export interface CloudConnectionResponse {
  connection_id: string;
  provider: string;
  display_name: string;
  linked_scopes: string[];
  target_scope: Record<string, string>;
  auth_mode: string;
  status: string;
  last_verified_at: string;
  last_scan_at: string;
  created_at: string;
  updated_at: string;
}

export async function createOnboardingSessionV1(
  body: OnboardingSessionCreateRequestV1,
): Promise<OnboardingSessionResponseV1> {
  const { data } = await apiClient.post<OnboardingSessionResponseV1>(
    "/v1/onboarding/sessions",
    body,
  );
  return data;
}

export async function getOnboardingSessionV1(
  sessionId: string,
): Promise<OnboardingSessionResponseV1> {
  const { data } = await apiClient.get<OnboardingSessionResponseV1>(
    `/v1/onboarding/sessions/${sessionId}`,
  );
  return data;
}

export async function generateOnboardingArtifactsV1(
  sessionId: string,
): Promise<OnboardingSessionResponseV1> {
  const { data } = await apiClient.post<OnboardingSessionResponseV1>(
    `/v1/onboarding/sessions/${sessionId}/generate-artifacts`,
  );
  return data;
}

export async function verifyOnboardingSessionV1(
  sessionId: string,
): Promise<OnboardingSessionResponseV1> {
  const { data } = await apiClient.post<OnboardingSessionResponseV1>(
    `/v1/onboarding/sessions/${sessionId}/verify`,
  );
  return data;
}

export async function connectOnboardingSessionV1(
  sessionId: string,
  scopeIds: string[],
): Promise<OnboardingSessionResponseV1> {
  const { data } = await apiClient.post<OnboardingSessionResponseV1>(
    `/v1/onboarding/sessions/${sessionId}/connect`,
    { scope_ids: scopeIds },
  );
  return data;
}

export async function listCloudConnectionsV1(): Promise<CloudConnectionResponse[]> {
  const { data } = await apiClient.get<CloudConnectionResponse[]>(
    "/v1/cloud-connections",
  );
  return data;
}

export async function refreshCloudConnectionV1(
  connectionId: string,
): Promise<CloudConnectionResponse> {
  const { data } = await apiClient.post<CloudConnectionResponse>(
    `/v1/cloud-connections/${connectionId}/refresh`,
  );
  return data;
}

export async function disconnectCloudConnectionV1(connectionId: string): Promise<void> {
  await apiClient.delete(`/v1/cloud-connections/${connectionId}`);
}
