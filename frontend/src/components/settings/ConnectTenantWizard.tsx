import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import {
  connectOnboardingSession,
  createOnboardingSession,
  discoverOnboardingSession,
  getOnboardingSession,
  markOnboardingReaderGranted,
  type OnboardingSessionResponse,
} from "../../api/subscriptions";
import { useSubscriptions } from "../../hooks/useSubscriptions";

const GUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

interface ApiErrorShape {
  response?: {
    data?: {
      detail?: string | { message?: string };
    };
  };
  message?: string;
}

function formatErr(err: unknown, fallback: string): string {
  const e = err as ApiErrorShape;
  const detail = e?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object" && detail.message) {
    return detail.message;
  }
  return e?.message ?? fallback;
}

function statusLabel(status: string): string {
  switch (status) {
    case "pending_consent":
      return "Waiting for Customer Admin Consent";
    case "pending_reader":
      return "Waiting for Reader Role Grant";
    case "pending_discovery":
      return "Ready to Discover Subscriptions";
    case "subscriptions_discovered":
      return "Subscriptions Discovered";
    case "completed":
      return "Completed";
    default:
      return status;
  }
}

export interface ConnectTenantWizardProps {
  onClose: () => void;
}

export function ConnectTenantWizard({ onClose }: ConnectTenantWizardProps) {
  const { refresh } = useSubscriptions();
  const [tenantId, setTenantId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [session, setSession] = useState<OnboardingSessionResponse | null>(null);

  const discoveredCount = useMemo(
    () => session?.discovered_subscription_ids.length ?? 0,
    [session],
  );

  const startSession = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setInfo(null);
    const tid = tenantId.trim().toLowerCase();
    if (!GUID_RE.test(tid)) {
      setError("Tenant ID must be a valid Azure AD tenant GUID.");
      return;
    }

    setBusy(true);
    try {
      const created = await createOnboardingSession(tid);
      setSession(created);
      setInfo("Session started. Continue with the actions below.");
    } catch (err) {
      setError(formatErr(err, "Failed to start onboarding session"));
    } finally {
      setBusy(false);
    }
  };

  const refreshSession = async () => {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      setSession(await getOnboardingSession(session.session_id));
    } catch (err) {
      setError(formatErr(err, "Failed to refresh onboarding status"));
    } finally {
      setBusy(false);
    }
  };

  const openConsent = () => {
    if (!session?.consent_url) return;
    window.open(session.consent_url, "_blank", "noopener,noreferrer");
  };

  const copyConsentUrl = async () => {
    if (!session?.consent_url) return;
    try {
      await navigator.clipboard.writeText(session.consent_url);
      setInfo("Consent URL copied. Share it with the customer admin.");
    } catch {
      setError("Unable to copy consent URL. Copy it manually from the field.");
    }
  };

  const markReader = async () => {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      setSession(await markOnboardingReaderGranted(session.session_id));
      setInfo("Reader role marked. Run discovery to list subscriptions.");
    } catch (err) {
      setError(formatErr(err, "Failed to mark Reader grant"));
    } finally {
      setBusy(false);
    }
  };

  const discover = async () => {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      const updated = await discoverOnboardingSession(session.session_id);
      setSession(updated);
      const discovered = updated.discovered_subscription_ids.length;
      if (discovered === 0) {
        setError("No subscriptions were discovered. Ensure Reader role is granted to CloudGuardIQ in this tenant, wait up to 5 minutes for RBAC propagation, then retry discovery.");
      }
      setInfo(`Discovered ${discovered} subscription(s).`);
    } catch (err) {
      setError(formatErr(err, "Failed to discover subscriptions"));
    } finally {
      setBusy(false);
    }
  };

  const connectAll = async () => {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      const updated = await connectOnboardingSession(
        session.session_id,
        session.discovered_subscription_ids,
      );
      setSession(updated);
      await refresh();
      setInfo(
        `Connected ${updated.connected_subscription_ids.length} subscription(s).`,
      );
    } catch (err) {
      setError(formatErr(err, "Failed to connect subscriptions"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="border-2 border-blue-300">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">Connect Customer Tenant</CardTitle>
        <Button variant="ghost" size="sm" onClick={onClose}>
          Close
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {info && (
          <Alert>
            <AlertDescription>{info}</AlertDescription>
          </Alert>
        )}

        {!session && (
          <form onSubmit={startSession} className="space-y-3">
            <div className="text-sm font-medium">Customer Tenant ID</div>
            <input
              type="text"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              placeholder="00000000-0000-0000-0000-000000000000"
              className="w-full rounded border px-3 py-2 font-mono text-xs"
              autoFocus
            />
            <div className="flex justify-end">
              <Button type="submit" disabled={busy || !tenantId.trim()}>
                {busy ? "Starting..." : "Start Onboarding"}
              </Button>
            </div>
          </form>
        )}

        {session && (
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-sm">
              <span className="font-medium">Status:</span>
              <Badge>{statusLabel(session.status)}</Badge>
            </div>
            <div className="text-xs text-[hsl(var(--muted-foreground))]">
              Session: <span className="font-mono">{session.session_id}</span>
            </div>
            <div className="text-xs text-[hsl(var(--muted-foreground))]">
              Tenant: <span className="font-mono">{session.customer_tenant_id}</span>
            </div>
            <div className="text-xs text-[hsl(var(--muted-foreground))]">
              Discovered: {discoveredCount} | Connected: {session.connected_subscription_ids.length}
            </div>

            {session.status === "subscriptions_discovered" && discoveredCount === 0 && (
              <Alert variant="destructive">
                <AlertDescription>
                  No subscriptions were returned by Azure for this tenant. Grant Reader to CloudGuardIQ service principal on target subscriptions, wait for RBAC propagation, and click Discover Subscriptions again.
                </AlertDescription>
              </Alert>
            )}

            {session.consent_url && (
              <div className="space-y-2 rounded border bg-[hsl(var(--muted))]/30 p-3">
                <div className="text-xs font-medium uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
                  Admin Consent URL (share with customer admin)
                </div>
                <textarea
                  value={session.consent_url}
                  readOnly
                  rows={3}
                  className="w-full resize-none rounded border bg-white px-2 py-1 font-mono text-xs"
                />
                <div className="flex flex-wrap gap-2">
                  <Button type="button" variant="outline" size="sm" onClick={copyConsentUrl}>
                    Copy URL
                  </Button>
                  <Button type="button" variant="outline" size="sm" onClick={openConsent}>
                    Open Admin Consent
                  </Button>
                </div>
              </div>
            )}

            <div className="flex flex-wrap gap-2 pt-2">
              {(session.status === "pending_reader" ||
                session.status === "pending_discovery") && (
                <Button variant="outline" onClick={markReader} disabled={busy}>
                  I Granted Reader Role
                </Button>
              )}

              {(session.status === "pending_discovery" ||
                session.status === "subscriptions_discovered") && (
                <Button variant="outline" onClick={discover} disabled={busy}>
                  Discover Subscriptions
                </Button>
              )}

              {session.status === "subscriptions_discovered" && (
                <Button onClick={connectAll} disabled={busy || discoveredCount === 0}>
                  Connect All Discovered
                </Button>
              )}

              <Button variant="ghost" onClick={refreshSession} disabled={busy}>
                Refresh Status
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
