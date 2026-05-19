import { useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { LoadingSpinner } from "../common/LoadingSpinner";
import { useSubscriptions } from "../../hooks/useSubscriptions";
import {
  discoverSubscriptions,
  getConsentUrl,
  getOnboardingTemplate,
  type DiscoveredSubscription,
  type OnboardingTemplateResponse,
} from "../../api/subscriptions";
import { getOnboardingInfo, type OnboardingInfo } from "../../api/onboarding";

const GUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

const STATE_STORAGE_KEY = "cguardiq.connectWizard";

export type WizardStep = "tenant" | "consent" | "reader" | "discover" | "done";

interface ApiErrorShape {
  response?: {
    status?: number;
    data?: {
      detail?:
        | string
        | {
            error?: string;
            message?: string;
            customer_tenant_id?: string;
            azure_principal_id?: string;
            template_uri?: string;
            deploy_url?: string;
          };
    };
  };
  message?: string;
}

function formatErr(err: unknown, fallback: string): string {
  const e = err as ApiErrorShape;
  const detail = e?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object" && detail.message)
    return detail.message;
  return e?.message ?? fallback;
}

function savePersisted(s: { tenantId: string; step: WizardStep } | null): void {
  try {
    if (s) sessionStorage.setItem(STATE_STORAGE_KEY, JSON.stringify(s));
    else sessionStorage.removeItem(STATE_STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

export interface ConnectTenantWizardProps {
  onClose: () => void;
  /** Initial state after consent callback resumes the wizard. */
  initialTenantId?: string;
  initialStep?: WizardStep;
}

export function ConnectTenantWizard({
  onClose,
  initialTenantId = "",
  initialStep = "tenant",
}: ConnectTenantWizardProps) {
  const { add, subscriptions } = useSubscriptions();
  const [step, setStep] = useState<WizardStep>(initialStep);
  const [tenantId, setTenantId] = useState<string>(initialTenantId);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [onboarding, setOnboarding] = useState<OnboardingInfo | null>(null);
  const [template, setTemplate] =
    useState<OnboardingTemplateResponse | null>(null);
  const [consentUrl, setConsentUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [deployCopied, setDeployCopied] = useState(false);
  const [principalCopied, setPrincipalCopied] = useState(false);
  const [discovered, setDiscovered] = useState<DiscoveredSubscription[]>([]);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [connectResults, setConnectResults] = useState<
    { subscription_id: string; display_name: string; ok: boolean; error?: string }[]
  >([]);

  useEffect(() => {
    let cancelled = false;
    getOnboardingInfo()
      .then((i) => { if (!cancelled) setOnboarding(i); })
      .catch(() => { if (!cancelled) setOnboarding(null); });
    return () => { cancelled = true; };
  }, []);

  // When entering the consent step, pre-fetch the consent URL so the
  // operator can copy/share it without first triggering a redirect.
  useEffect(() => {
    if (step !== "consent" || !tenantId) return;
    let cancelled = false;
    setBusy(true);
    setError(null);
    setConsentUrl(null);
    getConsentUrl(tenantId)
      .then((r) => { if (!cancelled) setConsentUrl(r.consent_url); })
      .catch((err) => {
        if (cancelled) return;
        setError(formatErr(err, "Failed to build consent URL"));
      })
      .finally(() => { if (!cancelled) setBusy(false); });
    return () => { cancelled = true; };
  }, [step, tenantId]);

  // When stepping into the reader step, fetch the ARM template URL.
  useEffect(() => {
    if (step !== "reader" || !tenantId) return;
    let cancelled = false;
    setBusy(true);
    setError(null);
    getOnboardingTemplate(tenantId, "managementGroup")
      .then((tpl) => { if (!cancelled) setTemplate(tpl); })
      .catch((err) => {
        if (cancelled) return;
        setError(formatErr(err, "Failed to load deployment template"));
      })
      .finally(() => { if (!cancelled) setBusy(false); });
    return () => { cancelled = true; };
  }, [step, tenantId]);

  const handleSubmitTenant = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const tid = tenantId.trim().toLowerCase();
    if (!GUID_RE.test(tid)) {
      setError("Tenant ID must be a valid Azure AD tenant GUID.");
      return;
    }
    setTenantId(tid);
    setStep("consent");
  };

  const handleOpenConsent = async () => {
    setError(null);
    try {
      const url = consentUrl ?? (await getConsentUrl(tenantId)).consent_url;
      // Persist so we can resume after the same-tab redirect.
      savePersisted({ tenantId, step: "reader" });
      window.location.href = url;
    } catch (err) {
      setError(formatErr(err, "Failed to build consent URL"));
    }
  };

  const handleCopyConsentUrl = async () => {
    if (!consentUrl) return;
    try {
      await navigator.clipboard.writeText(consentUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API can be blocked by permissions; fall back to a
      // manual-select hint instead of failing silently.
      setError(
        "Clipboard blocked. Select the URL above and copy it manually (Ctrl+C).",
      );
    }
  };

  const handleCopyDeployUrl = async () => {
    const url = template?.deploy_url;
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      setDeployCopied(true);
      setTimeout(() => setDeployCopied(false), 2000);
    } catch {
      setError(
        "Clipboard blocked. Select the URL above and copy it manually (Ctrl+C).",
      );
    }
  };

  const handleCopyPrincipalId = async () => {
    const pid = template?.azure_principal_id;
    if (!pid) return;
    try {
      await navigator.clipboard.writeText(pid);
      setPrincipalCopied(true);
      setTimeout(() => setPrincipalCopied(false), 2000);
    } catch {
      setError(
        "Clipboard blocked. Select the principal id and copy it manually (Ctrl+C).",
      );
    }
  };

  const handleSkipConsent = () => {
    // Async / link-based flow: operator emailed the URL to the customer
    // admin. Advance to the Reader step; if consent has not actually been
    // recorded yet, discover() in step 4 will surface the error.
    setError(null);
    setStep("reader");
  };

  const handleDiscover = async () => {
    setError(null);
    setBusy(true);
    try {
      const res = await discoverSubscriptions(tenantId);
      setDiscovered(res.subscriptions);
      const next: Record<string, boolean> = {};
      for (const s of res.subscriptions) {
        if (!s.already_linked) next[s.subscription_id] = false;
      }
      setSelected(next);
      setStep("discover");
    } catch (err) {
      const e = err as ApiErrorShape;
      const detail = e?.response?.data?.detail;
      if (
        e?.response?.status === 400 &&
        detail &&
        typeof detail === "object" &&
        detail.error === "reader_role_required"
      ) {
        // Surface the deploy template inline -- update template state and stay
        // on the reader step.
        setTemplate({
          customer_tenant_id: detail.customer_tenant_id ?? tenantId,
          azure_principal_id: detail.azure_principal_id ?? "",
          template_uri: detail.template_uri ?? "",
          deploy_url: detail.deploy_url ?? "",
          scope: "managementGroup",
        });
        setError(
          detail.message ??
            "Reader role not yet detected. Deploy the template and retry.",
        );
      } else {
        setError(formatErr(err, "Failed to discover subscriptions"));
      }
    } finally {
      setBusy(false);
    }
  };

  const toggleSelected = (sid: string) => {
    setSelected((prev) => ({ ...prev, [sid]: !prev[sid] }));
  };

  const selectedIds = useMemo(
    () => Object.entries(selected).filter(([, v]) => v).map(([k]) => k),
    [selected],
  );

  const handleConnect = async () => {
    setError(null);
    setInfo(null);
    if (selectedIds.length === 0) {
      setError("Pick at least one subscription to connect.");
      return;
    }
    setBusy(true);
    const results: typeof connectResults = [];
    for (const sid of selectedIds) {
      const found = discovered.find((d) => d.subscription_id === sid);
      const name = found?.display_name ?? "";
      try {
        await add(sid, name, tenantId);
        results.push({ subscription_id: sid, display_name: name, ok: true });
      } catch (err) {
        results.push({
          subscription_id: sid,
          display_name: name,
          ok: false,
          error: formatErr(err, "POST /subscriptions failed"),
        });
      }
    }
    setConnectResults(results);
    setBusy(false);
    setStep("done");
    savePersisted(null);
  };

  const handleClose = () => {
    savePersisted(null);
    onClose();
  };

  const linkedIds = useMemo(
    () => new Set(subscriptions.map((s) => s.subscription_id)),
    [subscriptions],
  );

  return (
    <Card className="border-2 border-blue-300">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">
          Connect another tenant
          <span className="ml-2 text-xs font-normal text-[hsl(var(--muted-foreground))]">
            Step {stepIndex(step)} of 4
          </span>
        </CardTitle>
        <Button variant="ghost" size="sm" onClick={handleClose}>
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

        {step === "tenant" && (
          <form onSubmit={handleSubmitTenant} className="space-y-2">
            <div className="text-sm font-medium">
              1. Enter the customer's Azure AD tenant ID
            </div>
            <p className="text-xs text-[hsl(var(--muted-foreground))]">
              You can find this in the Azure portal under{" "}
              <span className="font-mono">Entra ID &rarr; Overview &rarr; Tenant ID</span>.
            </p>
            <input
              type="text"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              placeholder="00000000-0000-0000-0000-000000000000"
              className="w-full rounded border px-3 py-2 font-mono text-xs"
              autoFocus
            />
            <div className="flex justify-end gap-2">
              <Button type="submit" disabled={!tenantId.trim()}>
                Continue
              </Button>
            </div>
          </form>
        )}

        {step === "consent" && (
          <div className="space-y-3">
            <div className="text-sm font-medium">
              2. Grant CloudGuardIQ admin consent
            </div>
            <p className="text-xs text-[hsl(var(--muted-foreground))]">
              A Global Administrator in tenant{" "}
              <span className="font-mono">{tenantId}</span> must approve
              CloudGuardIQ's read-only Azure permissions. Send the URL
              below to the customer admin (or open it yourself if you have
              that role). Azure AD will redirect them back to CloudGuardIQ
              and consent is recorded automatically.
            </p>
            {busy && !consentUrl && <LoadingSpinner />}
            {consentUrl && (
              <div className="space-y-2">
                <label
                  htmlFor="cguardiq-consent-url"
                  className="block text-xs font-medium text-[hsl(var(--muted-foreground))]"
                >
                  Admin-consent URL (copy &amp; email to the customer admin)
                </label>
                <div className="flex gap-2">
                  <input
                    id="cguardiq-consent-url"
                    type="text"
                    value={consentUrl}
                    readOnly
                    onClick={(e) => (e.target as HTMLInputElement).select()}
                    className="flex-1 rounded border px-2 py-1 text-xs font-mono"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={handleCopyConsentUrl}
                  >
                    {copied ? "Copied" : "Copy"}
                  </Button>
                </div>
                <p className="text-xs text-[hsl(var(--muted-foreground))]">
                  Sample email body:{" "}
                  <em>
                    "Please open this link in tenant {tenantId} and click
                    Accept to grant CloudGuardIQ read-only access."
                  </em>
                </p>
              </div>
            )}
            <div className="flex flex-wrap justify-between gap-2 pt-2">
              <Button variant="outline" onClick={() => setStep("tenant")}>
                Back
              </Button>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  onClick={handleSkipConsent}
                  disabled={!consentUrl}
                >
                  I've sent the link &mdash; continue
                </Button>
                <Button
                  onClick={handleOpenConsent}
                  disabled={busy || !consentUrl}
                >
                  Open consent in this tab
                </Button>
              </div>
            </div>
          </div>
        )}

        {step === "reader" && (
          <div className="space-y-3">
            <div className="text-sm font-medium">
              3. Grant Reader access on Azure subscriptions
            </div>
            <p className="text-xs text-[hsl(var(--muted-foreground))]">
              CloudGuardIQ needs the{" "}
              <span className="font-mono">Reader</span> role on the
              subscriptions you want to monitor. Deploy this one-click ARM
              template to grant it at the tenant root management group (covers
              every current and future subscription).
            </p>
            {busy && <LoadingSpinner />}
            {template && template.deploy_url && (
              <div className="space-y-2">
                <a
                  href={template.deploy_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center justify-center rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
                >
                  Deploy to Azure
                </a>
                <label
                  htmlFor="cguardiq-deploy-url"
                  className="block text-xs font-medium text-[hsl(var(--muted-foreground))]"
                >
                  Or copy &amp; email this URL to the customer subscription
                  Owner
                </label>
                <div className="flex gap-2">
                  <input
                    id="cguardiq-deploy-url"
                    type="text"
                    value={template.deploy_url}
                    readOnly
                    onClick={(e) => (e.target as HTMLInputElement).select()}
                    className="flex-1 rounded border px-2 py-1 text-xs font-mono"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={handleCopyDeployUrl}
                  >
                    {deployCopied ? "Copied" : "Copy"}
                  </Button>
                </div>
                {template.azure_principal_id && (
                  <>
                    <label
                      htmlFor="cguardiq-principal-id"
                      className="block text-xs font-medium text-[hsl(var(--muted-foreground))]"
                    >
                      Paste this into the &quot;Cloud Guard IQ Principal
                      Id&quot; field on the Azure Portal page
                    </label>
                    <div className="flex gap-2">
                      <input
                        id="cguardiq-principal-id"
                        type="text"
                        value={template.azure_principal_id}
                        readOnly
                        onClick={(e) =>
                          (e.target as HTMLInputElement).select()
                        }
                        className="flex-1 rounded border px-2 py-1 text-xs font-mono"
                      />
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={handleCopyPrincipalId}
                      >
                        {principalCopied ? "Copied" : "Copy"}
                      </Button>
                    </div>
                  </>
                )}
                <p className="text-xs text-[hsl(var(--muted-foreground))]">
                  Sample email body:{" "}
                  <em>
                    "Please open this link signed in to tenant {tenantId}
                    and click Review + create to assign Reader to the
                    CloudGuardIQ service principal."
                  </em>
                </p>
              </div>
            )}
            {onboarding && (
              <details className="text-xs">
                <summary className="cursor-pointer text-[hsl(var(--muted-foreground))]">
                  Or run this Azure CLI command instead
                </summary>
                <pre className="mt-2 overflow-x-auto rounded bg-black/80 p-2 text-xs text-emerald-300">
{`az role assignment create \
  --assignee ${template?.azure_principal_id ?? onboarding.azure_principal_id} \
  --role Reader \
  --scope /providers/Microsoft.Management/managementGroups/${tenantId}`}
                </pre>
              </details>
            )}
            <div className="flex justify-between gap-2 pt-2">
              <Button variant="outline" onClick={() => setStep("consent")}>
                Back
              </Button>
              <Button onClick={handleDiscover} disabled={busy}>
                {busy ? "Checking…" : "I've granted Reader — discover subscriptions"}
              </Button>
            </div>
          </div>
        )}

        {step === "discover" && (
          <div className="space-y-3">
            <div className="text-sm font-medium">
              4. Pick subscriptions to connect
            </div>
            <p className="text-xs text-[hsl(var(--muted-foreground))]">
              Found {discovered.length} subscription(s) in tenant{" "}
              <span className="font-mono">{tenantId}</span>.
            </p>
            <div className="max-h-72 overflow-y-auto rounded border">
              <table className="w-full text-xs">
                <thead className="bg-[hsl(var(--muted))] text-left">
                  <tr>
                    <th className="px-2 py-1 w-8"></th>
                    <th className="px-2 py-1">Name</th>
                    <th className="px-2 py-1">Subscription ID</th>
                    <th className="px-2 py-1">State</th>
                  </tr>
                </thead>
                <tbody>
                  {discovered.map((d) => {
                    const alreadyLinked =
                      d.already_linked || linkedIds.has(d.subscription_id);
                    return (
                      <tr
                        key={d.subscription_id}
                        className="border-t hover:bg-[hsl(var(--accent))]"
                      >
                        <td className="px-2 py-1">
                          <input
                            type="checkbox"
                            disabled={alreadyLinked}
                            checked={!!selected[d.subscription_id]}
                            onChange={() => toggleSelected(d.subscription_id)}
                          />
                        </td>
                        <td className="px-2 py-1">{d.display_name}</td>
                        <td className="px-2 py-1 font-mono">
                          {d.subscription_id}
                        </td>
                        <td className="px-2 py-1">
                          {alreadyLinked ? (
                            <Badge variant="secondary">Already linked</Badge>
                          ) : (
                            <Badge>{d.state}</Badge>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                  {discovered.length === 0 && (
                    <tr>
                      <td
                        colSpan={4}
                        className="px-2 py-3 text-center text-[hsl(var(--muted-foreground))]"
                      >
                        No subscriptions visible. Confirm the Reader role
                        assignment and retry.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <div className="flex justify-between gap-2">
              <Button variant="outline" onClick={() => setStep("reader")}>
                Back
              </Button>
              <Button
                onClick={handleConnect}
                disabled={busy || selectedIds.length === 0}
              >
                {busy
                  ? "Connecting…"
                  : `Connect ${selectedIds.length} subscription${selectedIds.length === 1 ? "" : "s"}`}
              </Button>
            </div>
          </div>
        )}

        {step === "done" && (
          <div className="space-y-3">
            <div className="text-sm font-medium">
              Done
            </div>
            <ul className="space-y-1 text-xs">
              {connectResults.map((r) => (
                <li key={r.subscription_id} className="flex items-start gap-2">
                  {r.ok ? (
                    <Badge>Connected</Badge>
                  ) : (
                    <Badge variant="destructive">Failed</Badge>
                  )}
                  <span className="font-mono">{r.subscription_id}</span>
                  {r.display_name && (
                    <span className="text-[hsl(var(--muted-foreground))]">
                      ({r.display_name})
                    </span>
                  )}
                  {r.error && (
                    <span className="text-red-600">— {r.error}</span>
                  )}
                </li>
              ))}
            </ul>
            <div className="flex justify-end">
              <Button onClick={handleClose}>Close</Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function stepIndex(step: WizardStep): number {
  switch (step) {
    case "tenant":
      return 1;
    case "consent":
      return 2;
    case "reader":
      return 3;
    case "discover":
    case "done":
      return 4;
  }
}
