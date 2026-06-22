import {
  PublicClientApplication,
  EventType,
  type AccountInfo,
  type EventMessage,
} from "@azure/msal-browser";
import {
  msalConfig,
  ciamMsalConfig,
  ciamEnabled,
  loginRequest,
  ciamLoginRequest,
  apiScopes,
  ciamApiScopes,
} from "./msalConfig";

// CloudGuardIQ supports two identity providers simultaneously:
//   * "workforce" -- Microsoft Entra ID work/school accounts (multi-tenant).
//   * "ciam"      -- Microsoft Entra External ID (email / Google) for
//                    AWS/GCP-only customers with no Azure tenant.
// Each is a distinct app registration, so each needs its own MSAL instance.
// The chosen provider is persisted so the correct instance is active after a
// login redirect round-trip.

export type AuthProvider = "workforce" | "ciam";

const PROVIDER_KEY = "cguardiq.authProvider";

export function getStoredProvider(): AuthProvider {
  try {
    if (localStorage.getItem(PROVIDER_KEY) === "ciam" && ciamEnabled) {
      return "ciam";
    }
  } catch {
    /* localStorage unavailable -- fall back to workforce. */
  }
  return "workforce";
}

function setStoredProvider(provider: AuthProvider): void {
  try {
    localStorage.setItem(PROVIDER_KEY, provider);
  } catch {
    /* localStorage unavailable -- nothing to persist. */
  }
}

export function clearStoredProvider(): void {
  try {
    localStorage.removeItem(PROVIDER_KEY);
  } catch {
    /* localStorage unavailable -- nothing to clear. */
  }
}

export const workforceMsalInstance = new PublicClientApplication(msalConfig);
export const ciamMsalInstance: PublicClientApplication | null = ciamEnabled
  ? new PublicClientApplication(ciamMsalConfig)
  : null;

export function getActiveMsalInstance(): PublicClientApplication {
  if (getStoredProvider() === "ciam" && ciamMsalInstance) {
    return ciamMsalInstance;
  }
  return workforceMsalInstance;
}

export function getActiveApiScopes(): { scopes: string[] } {
  return getStoredProvider() === "ciam" ? ciamApiScopes : apiScopes;
}

async function initInstance(instance: PublicClientApplication): Promise<void> {
  await instance.initialize();
  try {
    const response = await instance.handleRedirectPromise();
    if (response?.account) {
      instance.setActiveAccount(response.account);
    }
  } catch (error) {
    console.error("Redirect error:", error);
  }
  const accounts = instance.getAllAccounts();
  if (accounts.length > 0 && !instance.getActiveAccount()) {
    instance.setActiveAccount(accounts[0]);
  }
  instance.addEventCallback((event: EventMessage) => {
    if (event.eventType === EventType.LOGIN_SUCCESS && event.payload) {
      const payload = event.payload as { account: AccountInfo };
      instance.setActiveAccount(payload.account);
    }
  });
}

export async function initializeMsal(): Promise<void> {
  await initInstance(workforceMsalInstance);
  if (ciamMsalInstance) {
    await initInstance(ciamMsalInstance);
  }
}

export async function loginWithMicrosoft(): Promise<void> {
  setStoredProvider("workforce");
  await workforceMsalInstance.loginRedirect(loginRequest);
}

export async function loginWithCiam(): Promise<void> {
  if (!ciamMsalInstance) return;
  setStoredProvider("ciam");
  await ciamMsalInstance.loginRedirect(ciamLoginRequest);
}
