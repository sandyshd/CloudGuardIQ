import { Configuration, LogLevel } from "@azure/msal-browser";

const clientId = import.meta.env.VITE_AZURE_CLIENT_ID || "00000000-0000-0000-0000-000000000000";

// CloudGuardIQ is a multi-tenant SaaS. The MSAL authority MUST NOT be pinned to
// the CloudGuardIQ home tenant -- doing so causes external customer accounts to
// fail with "Selected user account does not exist in tenant 'Contoso'". Use
// `organizations` so each customer authenticates against their own Azure AD
// tenant. A specific tenant can still be forced for local/dev scenarios via
// VITE_AZURE_AUTHORITY_TENANT.
const authorityTenant =
  import.meta.env.VITE_AZURE_AUTHORITY_TENANT || "organizations";

const loggerOptions = {
  loggerCallback: (_level: LogLevel, message: string, containsPii: boolean) => {
    if (!containsPii) {
      console.log(message);
    }
  },
  logLevel: LogLevel.Warning,
  piiLoggingEnabled: false,
};

export const msalConfig: Configuration = {
  auth: {
    clientId,
    authority: `https://login.microsoftonline.com/${authorityTenant}`,
    redirectUri: import.meta.env.VITE_REDIRECT_URI || `${window.location.origin}/`,
    // Required for multi-tenant apps so MSAL accepts issuers from any tenant.
    knownAuthorities: ["login.microsoftonline.com"],
  },
  cache: {
    cacheLocation: "sessionStorage",
    storeAuthStateInCookie: false,
  },
  system: {
    loggerOptions,
  },
};

export const loginRequest = {
  scopes: [`${clientId}/.default`],
};

export const apiScopes = {
  scopes: [`${clientId}/.default`],
};

// ---------------------------------------------------------------------------
// Microsoft Entra External ID (CIAM) -- Phase 3
// ---------------------------------------------------------------------------
// Lets AWS/GCP-only customers sign up with email or Google without an Azure
// tenant. CIAM is a SEPARATE app registration (its own authority + clientId),
// so it gets its own MSAL configuration and instance. When the env vars are
// unset, CIAM is disabled and only the Microsoft work-account flow is shown.

const ciamClientId = import.meta.env.VITE_CIAM_CLIENT_ID || "";
// e.g. https://contoso.ciamlogin.com/<ciam-tenant-guid>
const ciamAuthority = import.meta.env.VITE_CIAM_AUTHORITY || "";

export const ciamEnabled = Boolean(ciamClientId && ciamAuthority);

function ciamKnownAuthorities(): string[] {
  if (!ciamAuthority) return [];
  try {
    return [new URL(ciamAuthority).host];
  } catch {
    return [];
  }
}

// Delegated API scope the SPA requests for the CloudGuardIQ API. Defaults to
// the app's `.default` (all statically configured permissions); override with
// VITE_CIAM_API_SCOPE when a custom scope (e.g. api://<id>/access_as_user) is
// exposed.
const ciamApiScope =
  import.meta.env.VITE_CIAM_API_SCOPE ||
  (ciamClientId ? `${ciamClientId}/.default` : "");

export const ciamMsalConfig: Configuration = {
  auth: {
    clientId: ciamClientId,
    authority: ciamAuthority,
    redirectUri: import.meta.env.VITE_REDIRECT_URI || `${window.location.origin}/`,
    knownAuthorities: ciamKnownAuthorities(),
  },
  cache: {
    cacheLocation: "sessionStorage",
    storeAuthStateInCookie: false,
  },
  system: {
    loggerOptions,
  },
};

export const ciamLoginRequest = {
  scopes: ciamApiScope ? [ciamApiScope] : ["openid", "profile", "email"],
};

export const ciamApiScopes = {
  scopes: ciamApiScope ? [ciamApiScope] : ["openid", "profile", "email"],
};
