import type { ReactNode } from "react";
import { useIsAuthenticated, useMsal } from "@azure/msal-react";
import { InteractionStatus } from "@azure/msal-browser";
import { loginRequest } from "./msalConfig";
import { Button } from "../components/ui/button";
import { Shield } from "lucide-react";

export function RequireAuth({ children }: { children: ReactNode }) {
  const isAuthenticated = useIsAuthenticated();
  const { instance, inProgress } = useMsal();

  if (inProgress !== InteractionStatus.None) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-[hsl(var(--primary))] border-t-transparent" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="flex h-screen flex-col items-center justify-center gap-6">
        <div className="flex items-center gap-3">
          <Shield className="h-10 w-10 text-[hsl(var(--primary))]" />
          <h1 className="text-3xl font-bold">CloudGuardIQ</h1>
        </div>
        <p className="text-[hsl(var(--muted-foreground))]">Cloud Security & FinOps Platform</p>
        <Button size="lg" onClick={() => instance.loginRedirect(loginRequest)}>
          Sign in with Azure AD
        </Button>
      </div>
    );
  }

  return <>{children}</>;
}
