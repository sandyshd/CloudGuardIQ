import { useEffect, useState } from "react";
import { MultiCloudOnboardingHub } from "../components/settings/MultiCloudOnboardingHub";
import { NotificationSettings } from "../components/settings/NotificationSettings";
import { SubscriptionList } from "../components/settings/SubscriptionList";
import { TierSelector } from "../components/settings/TierSelector";
import { Alert, AlertDescription } from "../components/ui/alert";
import { PageHeader } from "../components/common/PageHeader";
import { recordConsentCallback } from "../api/subscriptions";
import { PENDING_CONSENT_CALLBACK_KEY } from "../main";

import { toFriendlyMessage } from "../lib/errors";
const CONSENT_PARAM = "consent";

interface PendingConsentCallback {
  tenant: string;
  admin_consent: string;
  error: string;
  error_description: string;
  state: string;
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
      state: parsed.state ?? "",
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
    const stateParam = hasUrlCallback
      ? (params.get("state") ?? undefined)
      : (pending?.state || undefined);

    if (hasUrlCallback) {
      params.delete(CONSENT_PARAM);
      params.delete("tenant");
      params.delete("admin_consent");
      params.delete("error");
      params.delete("error_description");
      params.delete("state");
      const cleaned = url.pathname + (params.toString() ? `?${params}` : "");
      window.history.replaceState({}, "", cleaned);
    }

    if (errorParam) {
      setBanner({
        kind: "error",
        message: `Admin consent failed: ${errorDescription ?? errorParam}`,
      });
      return;
    }

    let cancelled = false;
    void (async () => {
      try {
        await recordConsentCallback(
          tenant,
          adminConsent,
          errorParam,
          errorDescription,
          stateParam,
        );
        if (cancelled) return;
        setBanner({
          kind: "info",
          message: "Admin consent recorded successfully.",
        });
      } catch (err) {
        if (cancelled) return;
        const msg =
          toFriendlyMessage(err, "Failed to record consent.");
        setBanner({ kind: "error", message: msg });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        subtitle="Connect cloud subscriptions, configure plans, and manage notifications."
      />
      {banner && (
        <Alert variant={banner.kind === "error" ? "destructive" : "default"}>
          <AlertDescription>{banner.message}</AlertDescription>
        </Alert>
      )}
      <div className="grid gap-4 md:grid-cols-2">
        <TierSelector />
        <NotificationSettings />
      </div>
      <MultiCloudOnboardingHub />
      <SubscriptionList />
    </div>
  );
}
