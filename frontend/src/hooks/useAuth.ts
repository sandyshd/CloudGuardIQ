import { useMsal, useIsAuthenticated } from "@azure/msal-react";
import { loginRequest } from "../auth/msalConfig";

export function useAuth() {
  const { instance, accounts } = useMsal();
  const isAuthenticated = useIsAuthenticated();

  const login = () => instance.loginRedirect(loginRequest);
  const logout = () => instance.logoutRedirect();

  const user = accounts[0] ? {
    name: accounts[0].name || "",
    email: accounts[0].username || "",
  } : null;

  return { isAuthenticated, user, login, logout };
}
