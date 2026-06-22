import { useMsal, useIsAuthenticated } from "@azure/msal-react";
import {
  loginWithMicrosoft,
  loginWithCiam,
  clearStoredProvider,
} from "../auth/instances";
import { ciamEnabled } from "../auth/msalConfig";

export function useAuth() {
  const { instance, accounts } = useMsal();
  const isAuthenticated = useIsAuthenticated();

  const login = () => loginWithMicrosoft();
  const loginCiam = () => loginWithCiam();
  const logout = () => {
    clearStoredProvider();
    return instance.logoutRedirect();
  };

  const user = accounts[0] ? {
    name: accounts[0].name || "",
    email: accounts[0].username || "",
  } : null;

  return { isAuthenticated, user, login, loginCiam, logout, ciamEnabled };
}
