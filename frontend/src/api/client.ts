import axios from "axios";
import { InteractionRequiredAuthError } from "@azure/msal-browser";
import {
  getActiveMsalInstance,
  getActiveApiScopes,
} from "../auth/instances";

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "/api",
  headers: {
    "Content-Type": "application/json",
  },
});

apiClient.interceptors.request.use(async (config) => {
  const msalInstance = getActiveMsalInstance();
  const apiScopes = getActiveApiScopes();
  const accounts = msalInstance.getAllAccounts();
  if (accounts.length > 0) {
    try {
      const response = await msalInstance.acquireTokenSilent({
        ...apiScopes,
        account: accounts[0],
      });
      config.headers.Authorization = `Bearer ${response.accessToken}`;
    } catch (error) {
      if (error instanceof InteractionRequiredAuthError) {
        // Only redirect for interactive auth errors, not network failures
        await msalInstance.acquireTokenRedirect(apiScopes);
      }
    }
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // Do not auto-redirect on 401 — let RequireAuth handle authentication
    return Promise.reject(error);
  }
);

export default apiClient;
