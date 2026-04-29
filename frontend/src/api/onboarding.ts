import apiClient from "./client";

export interface OnboardingInfo {
  azure_principal_id: string;
  azure_principal_display_name: string;
  role: string;
  az_command_template: string;
}

export async function getOnboardingInfo(): Promise<OnboardingInfo> {
  const { data } = await apiClient.get<OnboardingInfo>("/onboarding/info");
  return data;
}
