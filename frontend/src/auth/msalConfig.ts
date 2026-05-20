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
    loggerOptions: {
      loggerCallback: (_level, message, containsPii) => {
        if (!containsPii) {
          console.log(message);
        }
      },
      logLevel: LogLevel.Warning,
      piiLoggingEnabled: false,
    },
  },
};

export const loginRequest = {
  scopes: [`${clientId}/.default`],
};

export const apiScopes = {
  scopes: [`${clientId}/.default`],
};
