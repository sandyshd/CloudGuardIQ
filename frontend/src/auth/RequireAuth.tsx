import { useEffect, useState, type ReactNode } from "react";
import { useIsAuthenticated, useMsal } from "@azure/msal-react";
import { InteractionStatus } from "@azure/msal-browser";
import { loginRequest } from "./msalConfig";
import { Button } from "../components/ui/button";
import { getConfig } from "../api/config";

export function RequireAuth({ children }: { children: ReactNode }) {
  const isAuthenticated = useIsAuthenticated();
  const { instance, inProgress } = useMsal();
  const [demoMode, setDemoMode] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    getConfig()
      .then((cfg) => {
        if (!cancelled) setDemoMode(Boolean(cfg.demo_mode));
      })
      .catch(() => {
        if (!cancelled) setDemoMode(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (demoMode === null || inProgress !== InteractionStatus.None) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-[hsl(var(--primary))] border-t-transparent" />
      </div>
    );
  }

  // In demo mode the backend serves canned data without auth -- skip MSAL.
  if (demoMode) {
    return <>{children}</>;
  }

  if (!isAuthenticated) {
    return (
      <div className="flex h-screen flex-col items-center justify-center gap-6">
        <img
          src="/brand/cloudguardiq-primary-dark.svg"
          alt="CloudGuardIQ"
          className="h-12 w-auto select-none"
          draggable={false}
        />
        <p className="text-[hsl(var(--muted-foreground))]">Cloud Security & FinOps Platform</p>
        <Button size="lg" onClick={() => instance.loginRedirect(loginRequest)}>
          Sign in with Azure AD
        </Button>
      </div>
    );
  }

  return <>{children}</>;
}
