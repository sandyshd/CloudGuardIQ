import { Configuration, LogLevel } from "@azure/msal-browser";

const clientId = import.meta.env.VITE_AZURE_CLIENT_ID || "00000000-0000-0000-0000-000000000000";

export const msalConfig: Configuration = {
  auth: {
    clientId,
    authority: `https://login.microsoftonline.com/${import.meta.env.VITE_AZURE_TENANT_ID || "common"}`,
    redirectUri: import.meta.env.VITE_REDIRECT_URI || `${window.location.origin}/`,
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