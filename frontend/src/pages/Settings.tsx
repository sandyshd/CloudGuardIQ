import { useEffect, useState } from "react";
import { SubscriptionList } from "../components/settings/SubscriptionList";
import { NotificationSettings } from "../components/settings/NotificationSettings";
import { TierSelector } from "../components/settings/TierSelector";
import { Alert, AlertDescription } from "../components/ui/alert";
import { recordConsentCallback } from "../api/subscriptions";
import { PENDING_CONSENT_CALLBACK_KEY } from "../main";

const CONSENT_PARAM = "consent";

interface PendingConsentCallback {
  tenant: string;
  admin_consent: string;
  error: string;
  error_description: string;
}

function readPendingConsentCallback(): PendingConsentCallback | null {
  try {
    const raw = sessionStorage.getItem(PENDING_CONSENT_CALLBACK_KEY);
    if (!raw) return null;
    sessionStorage.removeItem(PENDING_CONSENT_CALLBACK_KEY);
    const parsed = JSON.parse(raw) as Partial<PendingConsentCallback>;
    return {
      tenant: parsed.tenant ?? "",
      admin_consent: parsed.admin_consent ?? "",
      error: parsed.error ?? "",
      error_description: parsed.error_description ?? "",
    };
  } catch {
    return null;
  }
}

interface ConsentBanner {
  kind: "info" | "error";
  message: string;
}

export function Settings() {
  const [banner, setBanner] = useState<ConsentBanner | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const url = new URL(window.location.href);
    const params = url.searchParams;
    const hasUrlCallback = params.get(CONSENT_PARAM) === "callback";
    const pending = hasUrlCallback ? null : readPendingConsentCallback();
    if (!hasUrlCallback && !pending) return;

    const tenant = hasUrlCallback
      ? (params.get("tenant") ?? "")
      : (pending?.tenant ?? "");
    const adminConsent = hasUrlCallback
      ? (params.get("admin_consent") ?? "")
      : (pending?.admin_consent ?? "");
    const errorParam = hasUrlCallback
      ? (params.get("error") ?? undefined)
      : (pending?.error || undefined);
    const errorDescription = hasUrlCallback
      ? (params.get("error_description") ?? undefined)
      : (pending?.error_description || undefined);

    // Strip the callback params from the visible URL immediately so a refresh
    // does not re-trigger this handler.
    if (hasUrlCallback) {
      params.delete(CONSENT_PARAM);
      params.delete("tenant");
      params.delete("admin_consent");
      params.delete("error");
      params.delete("error_description");
      const cleaned = url.pathname + (params.toString() ? `?${params}` : "");
      window.history.replaceState({}, "", cleaned);
    }

    if (errorParam) {
      setBanner({
        kind: "error",
        message: `Admin consent failed: ${errorDescription ?? errorParam}`,
      });
      try {
        sessionStorage.removeItem("cguardiq.connectWizard");
      } catch {
        /* ignore */
      }
      return;
    }

    let cancelled = false;
    void (async () => {
      try {
        await recordConsentCallback(tenant, adminConsent, errorParam, errorDescription);
        if (cancelled) return;
        // Resume the wizard at the Reader-role step.
        try {
          sessionStorage.setItem(
            "cguardiq.connectWizard",
            JSON.stringify({ tenantId: tenant.toLowerCase(), step: "reader" }),
          );
        } catch {
          /* ignore */
        }
        setBanner({
          kind: "info",
          message:
            "Admin consent recorded. Continue the wizard to grant Reader access on the subscriptions you want to monitor.",
        });
        // Force SubscriptionList to re-mount so its mount effect re-reads the
        // freshly-primed sessionStorage and re-opens the wizard at step 3.
        setRefreshKey((k) => k + 1);
      } catch (err) {
        if (cancelled) return;
        const msg =
          err instanceof Error ? err.message : "Failed to record consent.";
        setBanner({ kind: "error", message: msg });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>
      {banner && (
        <Alert variant={banner.kind === "error" ? "destructive" : "default"}>
          <AlertDescription>{banner.message}</AlertDescription>
        </Alert>
      )}
      <div className="grid gap-4 md:grid-cols-2">
        <TierSelector />
        <NotificationSettings />
      </div>
      <SubscriptionList key={refreshKey} />
    </div>
  );
}
