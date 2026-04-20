import axios from "axios";
import { msalInstance } from "../main";
import { apiScopes } from "../auth/msalConfig";

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "/api",
  headers: {
    "Content-Type": "application/json",
  },
});

apiClient.interceptors.request.use(async (config) => {
  const accounts = msalInstance.getAllAccounts();
  if (accounts.length > 0) {
    try {
      const response = await msalInstance.acquireTokenSilent({
        ...apiScopes,
        account: accounts[0],
      });
      config.headers.Authorization = `Bearer ${response.accessToken}`;
    } catch {
      // Token acquisition failed silently; request proceeds without auth
    }
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      msalInstance.loginRedirect(apiScopes);
    }
    return Promise.reject(error);
  }
);

export default apiClient;
