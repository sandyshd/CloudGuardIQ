import { useEffect, useState, type ReactNode } from "react";
import { useIsAuthenticated, useMsal } from "@azure/msal-react";
import { InteractionStatus } from "@azure/msal-browser";
import { ciamEnabled } from "./msalConfig";
import { loginWithCiam, loginWithMicrosoft } from "./instances";
import { Button } from "../components/ui/button";
import { getConfig } from "../api/config";

export function RequireAuth({ children }: { children: ReactNode }) {
  const isAuthenticated = useIsAuthenticated();
  const { inProgress } = useMsal();
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
      <LoginScreen
        onSignIn={loginWithMicrosoft}
        onSignInCiam={loginWithCiam}
        ciamEnabled={ciamEnabled}
      />
    );
  }

  return <>{children}</>;
}

function LoginScreen({
  onSignIn,
  onSignInCiam,
  ciamEnabled,
}: {
  onSignIn: () => void;
  onSignInCiam: () => void;
  ciamEnabled: boolean;
}) {
  return (
    <div className="flex min-h-screen flex-col bg-[hsl(var(--sidebar-background))] text-[hsl(var(--foreground))]">
      {/* Top bar (dark, sidebar color) -- logo lives here */}
      <header className="flex items-center justify-between px-6 py-4 sm:px-10">
        <img
          src="/brand/cloudguardiq-primary-dark.svg"
          alt="CloudGuardIQ"
          className="h-16 w-auto select-none"
          draggable={false}
        />
        <a
          href="#"
          className="hidden text-sm text-[hsl(var(--sidebar-foreground))] hover:text-[hsl(var(--sidebar-accent-foreground))] sm:inline"
        >
          Contact sales
        </a>
      </header>

      {/* Main panel (light background with ambient gradients) */}
      <main className="relative flex flex-1 overflow-hidden bg-[hsl(var(--background))]">
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 bg-[radial-gradient(80%_60%_at_15%_10%,hsl(var(--primary)/0.18),transparent_60%),radial-gradient(70%_55%_at_90%_90%,hsl(var(--accent)/0.18),transparent_60%)]"
        />
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 opacity-[0.07] [background-image:linear-gradient(hsl(var(--foreground))_1px,transparent_1px),linear-gradient(90deg,hsl(var(--foreground))_1px,transparent_1px)] [background-size:40px_40px]"
        />

        <div className="relative mx-auto grid w-full max-w-7xl flex-1 grid-cols-1 items-center gap-10 px-6 py-12 sm:px-10 lg:grid-cols-2">
          {/* Left: value props */}
          <section className="hidden flex-col gap-8 lg:flex">
            <div className="space-y-4">
              <span className="inline-flex items-center gap-2 rounded-full border border-[hsl(var(--border))] bg-[hsl(var(--card))]/70 px-3 py-1 text-xs font-medium text-[hsl(var(--muted-foreground))] backdrop-blur">
                <span className="h-1.5 w-1.5 rounded-full bg-[hsl(var(--success))]" />
                152 native rules · Azure · AWS · GCP
              </span>
              <h1 className="text-4xl font-semibold leading-tight tracking-tight md:text-5xl">
                Unified cloud security
                <br />
                <span className="bg-gradient-to-r from-[hsl(var(--primary))] to-[hsl(var(--accent))] bg-clip-text text-transparent">
                  &amp; FinOps governance.
                </span>
              </h1>
              <p className="max-w-md text-base text-[hsl(var(--muted-foreground))]">
                Continuous CSPM posture, cost waste detection, and
                AI-generated remediation — all without a hard dependency on
                Defender for Cloud.
              </p>
            </div>

            <ul className="grid max-w-md grid-cols-1 gap-3 text-sm sm:grid-cols-2">
              {[
                { title: "Multi-cloud", body: "Azure, AWS &amp; GCP scanners" },
                { title: "AI remediation", body: "GPT-5.1 fix templates" },
                { title: "FinOps", body: "Waste &amp; rightsizing" },
                { title: "Compliance", body: "SOC2 · CIS · NIST · PCI · ISO · HIPAA" },
              ].map((feature) => (
                <li
                  key={feature.title}
                  className="rounded-xl border border-[hsl(var(--border))] bg-[hsl(var(--card))]/60 p-3 backdrop-blur"
                >
                  <p className="font-medium">{feature.title}</p>
                  <p
                    className="text-xs text-[hsl(var(--muted-foreground))]"
                    dangerouslySetInnerHTML={{ __html: feature.body }}
                  />
                </li>
              ))}
            </ul>
          </section>

          {/* Right: sign-in card */}
          <section className="flex items-center justify-center">
            <div className="w-full max-w-md">
              <div className="rounded-2xl border border-[hsl(var(--border))] bg-[hsl(var(--card))]/85 p-8 shadow-xl shadow-black/5 backdrop-blur-xl">
                <div className="space-y-2 text-center">
                  <h2 className="text-2xl font-semibold tracking-tight">
                    Welcome back
                  </h2>
                  <p className="text-sm text-[hsl(var(--muted-foreground))]">
                    {ciamEnabled
                      ? "Sign in with your work account, or sign up with email or Google."
                      : "Sign in with your work account to access your tenant."}
                  </p>
                </div>

                <div className="mt-8 space-y-3">
                  <Button
                    size="lg"
                    className="w-full gap-2"
                    onClick={onSignIn}
                  >
                    <MicrosoftLogo className="h-4 w-4" />
                    Sign in with Microsoft
                  </Button>
                  {ciamEnabled && (
                    <>
                      <div className="flex items-center gap-3 text-[10px] uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                        <span className="h-px flex-1 bg-[hsl(var(--border))]" />
                        <span>or</span>
                        <span className="h-px flex-1 bg-[hsl(var(--border))]" />
                      </div>
                      <Button
                        size="lg"
                        variant="outline"
                        className="w-full gap-2"
                        onClick={onSignInCiam}
                      >
                        <GoogleLogo className="h-4 w-4" />
                        Sign up with email or Google
                      </Button>
                      <p className="text-center text-xs text-[hsl(var(--muted-foreground))]">
                        For AWS &amp; GCP customers — no Azure account needed
                      </p>
                    </>
                  )}
                  {!ciamEnabled && (
                    <p className="text-center text-xs text-[hsl(var(--muted-foreground))]">
                      Single sign-on via Microsoft Entra ID
                    </p>
                  )}
                </div>

                <div className="my-6 flex items-center gap-3 text-[10px] uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                  <span className="h-px flex-1 bg-[hsl(var(--border))]" />
                  <span>Secure by design</span>
                  <span className="h-px flex-1 bg-[hsl(var(--border))]" />
                </div>

                <ul className="space-y-2 text-xs text-[hsl(var(--muted-foreground))]">
                  <li className="flex items-center gap-2">
                    <CheckIcon /> Zero credentials stored — tokens minted via OBO
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckIcon /> Read-only cloud access by default
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckIcon /> Customer data isolated per tenant
                  </li>
                </ul>
              </div>

              <p className="mt-6 text-center text-xs text-[hsl(var(--muted-foreground))]">
                By signing in you accept our{" "}
                <a href="#" className="underline underline-offset-2 hover:text-[hsl(var(--foreground))]">
                  Terms
                </a>{" "}
                and{" "}
                <a href="#" className="underline underline-offset-2 hover:text-[hsl(var(--foreground))]">
                  Privacy Policy
                </a>
                .
              </p>
            </div>
          </section>
        </div>
      </main>

      {/* Bottom bar (dark, sidebar color) */}
      <footer className="flex flex-col items-center justify-between gap-2 border-t border-[hsl(var(--sidebar-border))] px-6 py-4 text-xs text-[hsl(var(--sidebar-foreground))] sm:flex-row sm:px-10">
        <span>© {new Date().getFullYear()} CloudGuardIQ · Cloud Security &amp; FinOps Platform</span>
        <span className="text-[hsl(var(--sidebar-muted))]">SOC2 · CIS · NIST · PCI · ISO · HIPAA ready</span>
      </footer>
    </div>
  );
}

function GoogleLogo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 48 48" className={className} aria-hidden>
      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
      <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
      <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
    </svg>
  );
}

function MicrosoftLogo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 23 23" className={className} aria-hidden>
      <rect x="1" y="1" width="10" height="10" fill="#F25022" />
      <rect x="12" y="1" width="10" height="10" fill="#7FBA00" />
      <rect x="1" y="12" width="10" height="10" fill="#00A4EF" />
      <rect x="12" y="12" width="10" height="10" fill="#FFB900" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg
      viewBox="0 0 20 20"
      className="h-3.5 w-3.5 flex-none text-[hsl(var(--success))]"
      fill="currentColor"
      aria-hidden
    >
      <path
        fillRule="evenodd"
        d="M16.704 5.29a1 1 0 0 1 .006 1.414l-7.07 7.13a1 1 0 0 1-1.42.003L3.29 8.92a1 1 0 1 1 1.42-1.41l3.213 3.232 6.36-6.413a1 1 0 0 1 1.42-.04Z"
        clipRule="evenodd"
      />
    </svg>
  );
}
