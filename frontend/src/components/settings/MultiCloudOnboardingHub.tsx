import { useEffect, useMemo, useState } from "react";
import { Alert, AlertDescription } from "../ui/alert";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../ui/table";
import { Info } from "lucide-react";
import { useSubscriptionContext } from "../../auth/SubscriptionContext";
import {
  connectOnboardingSessionV1,
  createOnboardingSessionV1,
  disconnectCloudConnectionV1,
  generateOnboardingArtifactsV1,
  getOnboardingSessionV1,
  listCloudConnectionsV1,
  refreshCloudConnectionV1,
  verifyOnboardingSessionV1,
  type CloudConnectionResponse,
  type CloudProvider,
  type OnboardingSessionResponseV1,
} from "../../api/onboardingV1";

type NoticeKind = "info" | "error" | "success";

interface Notice {
  kind: NoticeKind;
  message: string;
}

interface ErrorDetail {
  error_code?: string;
  message?: string;
  remediation?: string[];
}

interface ApiError {
  response?: {
    data?: {
      detail?: string | ErrorDetail;
    };
  };
  message?: string;
}

type StepId = 1 | 2 | 3 | 4 | 5;

interface StepDef {
  id: StepId;
  title: string;
  description: string;
}

const STEPS: ReadonlyArray<StepDef> = [
  {
    id: 1,
    title: "Choose Provider",
    description: "Pick a cloud and identify the account or tenant to enroll.",
  },
  {
    id: 2,
    title: "Grant Trust",
    description: "Generate artifacts and apply them in the provider console.",
  },
  {
    id: 3,
    title: "Verify",
    description: "Confirm CloudGuardIQ can authenticate and discover scopes.",
  },
  {
    id: 4,
    title: "Connect Scopes",
    description: "Select which subscriptions, accounts, or projects to monitor.",
  },
  {
    id: 5,
    title: "Done",
    description: "Connection established. Review or onboard another provider.",
  },
];

const PROVIDER_LABELS: Record<CloudProvider, string> = {
  AZURE: "Microsoft Azure",
  AWS: "Amazon Web Services",
  GCP: "Google Cloud Platform",
};

const URL_ARTIFACT_KEYS = new Set([
  "deploy_url",
  "template_uri",
  "parameters_uri",
  "consent_url",
  "cloudformation_template_url",
]);

const LONG_ARTIFACT_KEYS = new Set([
  "trust_policy_json",
  "gcloud_bind_command",
]);

const ARTIFACT_LABELS: Record<string, string> = {
  deploy_url: "Deploy to Azure",
  template_uri: "ARM template URI",
  parameters_uri: "ARM parameters URI",
  consent_url: "Tenant consent URL",
  azure_principal_id: "CloudGuardIQ principal ID",
  cloudformation_template_url: "CloudFormation Launch Stack URL",
  aws_account_id: "CloudGuardIQ AWS account",
  aws_external_id: "External ID (paste into IAM trust policy)",
  role_name: "IAM role name",
  trust_policy_json: "IAM role trust policy (JSON)",
  workload_identity_pool: "Workload Identity Pool",
  provider_resource_name: "Workload Identity Provider",
  service_account_email: "Service account to impersonate",
  gcloud_bind_command: "gcloud command to bind impersonation",
};

function artifactLabel(key: string): string {
  return ARTIFACT_LABELS[key] ?? key.replace(/_/g, " ");
}

function formatApiError(error: unknown, fallback: string): string {
  const parsed = error as ApiError;
  const detail = parsed?.response?.data?.detail;
  if (typeof detail === "string") {
    return detail;
  }
  if (detail && typeof detail === "object") {
    const remediation = detail.remediation && detail.remediation.length > 0
      ? ` (${detail.remediation.join(" ")})`
      : "";
    if (detail.message && detail.error_code) {
      return `${detail.error_code}: ${detail.message}${remediation}`;
    }
    if (detail.message) {
      return `${detail.message}${remediation}`;
    }
  }
  return parsed?.message ?? fallback;
}

function isoToLocal(value: string): string {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function statusVariant(status: string): "default" | "secondary" | "destructive" {
  if (status === "connected" || status === "verified" || status === "active" || status === "pass") {
    return "default";
  }
  if (status === "action_required" || status === "failed" || status === "disconnected" || status === "fail") {
    return "destructive";
  }
  return "secondary";
}

async function copyToClipboard(value: string): Promise<boolean> {
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {
    // fall through
  }
  return false;
}

function Stepper({ current }: { current: StepId }): JSX.Element {
  return (
    <ol className="grid gap-2 md:grid-cols-5">
      {STEPS.map((step) => {
        const state =
          step.id < current ? "done" : step.id === current ? "current" : "upcoming";
        const dotClasses =
          state === "done"
            ? "bg-[hsl(var(--success))] text-[hsl(var(--success-foreground,0_0%_100%))] border-[hsl(var(--success))]"
            : state === "current"
              ? "bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] border-[hsl(var(--primary))]"
              : "bg-white text-[hsl(var(--muted-foreground))] border-[hsl(var(--border))]";
        return (
          <li key={step.id} className="flex items-start gap-2">
            <div
              className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full border text-xs font-semibold ${dotClasses}`}
              aria-current={state === "current" ? "step" : undefined}
            >
              {state === "done" ? "✓" : step.id}
            </div>
            <div className="min-w-0">
              <div
                className={`text-sm font-medium ${
                  state === "upcoming" ? "text-[hsl(var(--muted-foreground))]" : ""
                }`}
              >
                {step.title}
              </div>
              <div className="text-xs text-[hsl(var(--muted-foreground))]">
                {step.description}
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

interface CopyButtonProps {
  value: string;
  label?: string;
}

function CopyButton({ value, label = "Copy" }: CopyButtonProps): JSX.Element {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="sm"
      variant="outline"
      type="button"
      onClick={async () => {
        const ok = await copyToClipboard(value);
        if (ok) {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        }
      }}
    >
      {copied ? "Copied!" : label}
    </Button>
  );
}

function ArtifactRow({ name, value }: { name: string; value: string }): JSX.Element {
  const isUrl = URL_ARTIFACT_KEYS.has(name) && /^https?:\/\//i.test(value);
  const isLong = LONG_ARTIFACT_KEYS.has(name) || value.length > 120;

  return (
    <div className="rounded border bg-white p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-sm font-medium">{artifactLabel(name)}</div>
          <div className="text-xs uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
            {name}
          </div>
        </div>
        <div className="flex gap-2">
          {isUrl && (
            <a
              href={value}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex h-9 items-center justify-center rounded-md bg-[hsl(var(--primary))] px-3 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:bg-[hsl(var(--primary)/0.9)]"
            >
              Open
            </a>
          )}
          <CopyButton value={value} />
        </div>
      </div>
      {isLong ? (
        <textarea
          value={value}
          readOnly
          rows={Math.min(8, Math.max(3, Math.ceil(value.length / 90)))}
          className="mt-2 w-full resize-y rounded border p-2 font-mono text-xs"
        />
      ) : (
        <div className="mt-2 break-all rounded border bg-[hsl(var(--muted))]/30 p-2 font-mono text-xs">
          {value}
        </div>
      )}
    </div>
  );
}

function AzureInstructions({ artifacts }: { artifacts: Record<string, string> }): JSX.Element {
  const deployUrl = artifacts.deploy_url;
  return (
    <ol className="list-decimal space-y-2 pl-5 text-sm">
      <li>
        Click <strong>Open</strong> next to <em>Deploy to Azure</em> below. The Azure Portal
        opens a deployment blade pre-filled with the CloudGuardIQ principal ID.
      </li>
      <li>
        Select the subscription you want to enroll, accept the terms, and click{" "}
        <strong>Create</strong>. This assigns the <code>Reader</code> role to CloudGuardIQ at
        the subscription scope.
      </li>
      <li>
        Wait for the Azure deployment to report <strong>Succeeded</strong>, then return here
        and continue to <strong>Verify</strong>.
      </li>
      {!deployUrl && (
        <li className="text-[hsl(var(--warning))]">
          Deploy URL is not available yet. Click <strong>Generate Artifacts</strong> above.
        </li>
      )}
    </ol>
  );
}

function AwsInstructions({ artifacts }: { artifacts: Record<string, string> }): JSX.Element {
  const cfnUrl = artifacts.cloudformation_template_url;
  return (
    <ol className="list-decimal space-y-2 pl-5 text-sm">
      <li>
        Sign in to the AWS account you are enrolling. Open the{" "}
        {cfnUrl ? (
          <a
            href={cfnUrl}
            target="_blank"
            rel="noreferrer noopener"
            className="font-medium text-[hsl(var(--primary))] underline"
          >
            CloudFormation Launch Stack
          </a>
        ) : (
          <span className="font-medium">CloudFormation Launch Stack</span>
        )}{" "}
        link.
      </li>
      <li>
        On the CloudFormation page, paste the <strong>External ID</strong> from the artifacts
        below into the stack parameter. The stack creates the IAM role{" "}
        <code>{artifacts.role_name ?? "CloudGuardIQReadOnlyRole"}</code> with read-only access.
      </li>
      <li>
        If you prefer manual setup, create an IAM role with the trust policy shown below and
        attach the AWS managed <code>SecurityAudit</code> and <code>ReadOnlyAccess</code>{" "}
        policies.
      </li>
      <li>
        Once the role exists, return here and continue to <strong>Verify</strong>.
      </li>
    </ol>
  );
}

function GcpInstructions({ artifacts }: { artifacts: Record<string, string> }): JSX.Element {
  return (
    <ol className="list-decimal space-y-2 pl-5 text-sm">
      <li>
        Open Google Cloud Shell or a terminal with <code>gcloud</code> authenticated against
        the project you are enrolling.
      </li>
      <li>
        Run the <strong>gcloud command</strong> shown below. It binds CloudGuardIQ's Workload
        Identity Pool principal to impersonate the read-only service account{" "}
        <code>{artifacts.service_account_email ?? "cloudguardiq-reader@…"}</code>.
      </li>
      <li>
        Grant the service account the <code>roles/viewer</code> and{" "}
        <code>roles/iam.securityReviewer</code> roles on the project (or run the additional
        commands listed by the generator).
      </li>
      <li>
        Return here and continue to <strong>Verify</strong>.
      </li>
    </ol>
  );
}

function ProviderInstructions({
  provider,
  artifacts,
}: {
  provider: CloudProvider;
  artifacts: Record<string, string>;
}): JSX.Element {
  if (provider === "AZURE") return <AzureInstructions artifacts={artifacts} />;
  if (provider === "AWS") return <AwsInstructions artifacts={artifacts} />;
  return <GcpInstructions artifacts={artifacts} />;
}

export function MultiCloudOnboardingHub(): JSX.Element {
  const [step, setStep] = useState<StepId>(1);

  const { refresh: refreshSubscriptions } = useSubscriptionContext();

  const [provider, setProvider] = useState<CloudProvider>("AZURE");
  const [displayName, setDisplayName] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [accountId, setAccountId] = useState("");
  const [awsRegion, setAwsRegion] = useState("us-east-1");
  const [projectId, setProjectId] = useState("");

  const [session, setSession] = useState<OnboardingSessionResponseV1 | null>(null);
  const [selectedScopeIds, setSelectedScopeIds] = useState<string[]>([]);

  const [connections, setConnections] = useState<CloudConnectionResponse[]>([]);
  const [connectionsLoading, setConnectionsLoading] = useState(false);

  const [busyAction, setBusyAction] = useState<string>("");
  const [notice, setNotice] = useState<Notice | null>(null);

  const discoveredScopeIds = useMemo(
    () => session?.discovered_scopes.map((scope) => scope.id) ?? [],
    [session],
  );

  useEffect(() => {
    void loadConnections();
  }, []);

  useEffect(() => {
    if (!session || session.discovered_scopes.length === 0) {
      return;
    }
    setSelectedScopeIds(session.discovered_scopes.map((scope) => scope.id));
  }, [session?.session_id, session?.discovered_scopes.length]);

  async function loadConnections(): Promise<void> {
    setConnectionsLoading(true);
    try {
      const result = await listCloudConnectionsV1();
      setConnections(result);
    } catch (error) {
      setNotice({
        kind: "error",
        message: formatApiError(error, "Failed to load cloud connections."),
      });
    } finally {
      setConnectionsLoading(false);
    }
  }

  function resetWizard(): void {
    setStep(1);
    setSession(null);
    setSelectedScopeIds([]);
    setDisplayName("");
    setTenantId("");
    setAccountId("");
    setAwsRegion("us-east-1");
    setProjectId("");
    setNotice(null);
  }

  async function startSession(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setNotice(null);

    const targetScope =
      provider === "AZURE"
        ? { tenant_id: tenantId.trim() }
        : provider === "AWS"
          ? { account_id: accountId.trim(), region: awsRegion.trim() }
          : { project_id: projectId.trim() };

    setBusyAction("create");
    try {
      const created = await createOnboardingSessionV1({
        provider,
        display_name: displayName.trim(),
        target_scope: targetScope,
      });
      setSession(created);
      setStep(2);
      setNotice({
        kind: "success",
        message: "Session created. Generate the artifacts and apply them in your provider.",
      });
    } catch (error) {
      setNotice({
        kind: "error",
        message: formatApiError(error, "Failed to create onboarding session."),
      });
    } finally {
      setBusyAction("");
    }
  }

  async function refreshSession(): Promise<void> {
    if (!session) {
      return;
    }
    setBusyAction("refresh-session");
    setNotice(null);
    try {
      const updated = await getOnboardingSessionV1(session.session_id);
      setSession(updated);
    } catch (error) {
      setNotice({
        kind: "error",
        message: formatApiError(error, "Failed to refresh session status."),
      });
    } finally {
      setBusyAction("");
    }
  }

  async function generateArtifacts(): Promise<void> {
    if (!session) {
      return;
    }
    setBusyAction("artifacts");
    setNotice(null);
    try {
      const updated = await generateOnboardingArtifactsV1(session.session_id);
      setSession(updated);
      setNotice({
        kind: "success",
        message:
          "Artifacts generated. Follow the steps below in your provider console, then continue to Verify.",
      });
    } catch (error) {
      setNotice({
        kind: "error",
        message: formatApiError(error, "Failed to generate onboarding artifacts."),
      });
    } finally {
      setBusyAction("");
    }
  }

  async function verifySession(): Promise<void> {
    if (!session) {
      return;
    }
    setBusyAction("verify");
    setNotice(null);
    try {
      const updated = await verifyOnboardingSessionV1(session.session_id);
      setSession(updated);
      const allPassed = updated.verification_checks.every((c) => c.status === "pass");
      if (allPassed && updated.discovered_scopes.length > 0) {
        setStep(4);
        setNotice({
          kind: "success",
          message: "Verification passed. Select the scopes you want CloudGuardIQ to monitor.",
        });
      } else if (updated.discovered_scopes.length === 0) {
        // Covers both ``all pass but 0 scopes`` and ``scope_discovery=warn``
        // emitted by the API when discovery returned an empty list. The
        // warn chip carries the full diagnostic; this banner gives the
        // top-line remediation including the "adding another subscription
        // later" path, which is easy to miss because the ARM template
        // only grants Reader at the subscription scope it was deployed
        // to.
        setNotice({
          kind: "info",
          message:
            "No new subscriptions were returned. If you are linking an additional subscription, go back to Step 2 and re-deploy the ARM template targeting the new subscription (or assign the CloudGuardIQ enterprise application the Reader role on it). Wait ~2 minutes for Azure RBAC to propagate, then re-run Verify.",
        });
      } else {
        setNotice({
          kind: "error",
          message:
            "One or more verification checks failed. Re-check the trust setup steps above, then re-run Verify.",
        });
      }
    } catch (error) {
      setNotice({
        kind: "error",
        message: formatApiError(error, "Verification failed."),
      });
    } finally {
      setBusyAction("");
    }
  }

  async function connectScopes(): Promise<void> {
    if (!session) {
      return;
    }

    const scopeIds = selectedScopeIds.length > 0 ? selectedScopeIds : discoveredScopeIds;
    if (scopeIds.length === 0) {
      setNotice({
        kind: "error",
        message: "No scopes selected. Run Verify first and choose at least one scope.",
      });
      return;
    }

    setBusyAction("connect");
    setNotice(null);
    try {
      const updated = await connectOnboardingSessionV1(session.session_id, scopeIds);
      setSession(updated);
      setStep(5);
      setNotice({
        kind: "success",
        message: `Connected. Connection ID: ${updated.connection_id}.`,
      });
      await loadConnections();
      try {
        await refreshSubscriptions();
      } catch {
        // Non-fatal: the dashboard will refresh on next page load.
      }
    } catch (error) {
      setNotice({
        kind: "error",
        message: formatApiError(error, "Failed to connect scopes."),
      });
    } finally {
      setBusyAction("");
    }
  }

  async function refreshConnection(connectionId: string): Promise<void> {
    setBusyAction(`connection-refresh-${connectionId}`);
    setNotice(null);
    try {
      await refreshCloudConnectionV1(connectionId);
      await loadConnections();
      setNotice({ kind: "info", message: "Connection refresh completed." });
    } catch (error) {
      setNotice({
        kind: "error",
        message: formatApiError(error, "Failed to refresh cloud connection."),
      });
    } finally {
      setBusyAction("");
    }
  }

  async function disconnectConnection(connectionId: string): Promise<void> {
    const confirmed = window.confirm(
      "Disconnect this cloud connection? Existing findings remain available by retention policy.",
    );
    if (!confirmed) {
      return;
    }
    setBusyAction(`connection-delete-${connectionId}`);
    setNotice(null);
    try {
      await disconnectCloudConnectionV1(connectionId);
      await loadConnections();
      setNotice({ kind: "info", message: "Cloud connection disconnected." });
    } catch (error) {
      setNotice({
        kind: "error",
        message: formatApiError(error, "Failed to disconnect cloud connection."),
      });
    } finally {
      setBusyAction("");
    }
  }

  function toggleScope(scopeId: string): void {
    setSelectedScopeIds((current) =>
      current.includes(scopeId)
        ? current.filter((id) => id !== scopeId)
        : [...current, scopeId],
    );
  }

  const hasArtifacts = !!session && Object.keys(session.artifacts).length > 0;
  const hasVerification = !!session && session.verification_checks.length > 0;
  const hasScopes = !!session && session.discovered_scopes.length > 0;

  const noticeVariant: "default" | "destructive" =
    notice?.kind === "error" ? "destructive" : "default";

  return (
    <div className="space-y-6">
      <Card className="border-[hsl(var(--primary)/0.3)]">
        <CardHeader>
          <CardTitle className="text-lg">Multi-Cloud Onboarding</CardTitle>
          <CardDescription>
            Enroll a cloud account in five guided steps. Works the same way for Azure, AWS, and
            GCP.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <Stepper current={step} />

          {notice && (
            <Alert variant={noticeVariant}>
              <AlertDescription>{notice.message}</AlertDescription>
            </Alert>
          )}

          {step === 1 && (
            <section className="space-y-4">
              <div
                role="note"
                className="flex items-start gap-2 rounded-md border border-[hsl(var(--primary)/0.3)] bg-[hsl(var(--primary)/0.06)] p-3 text-sm text-[hsl(var(--foreground))]"
              >
                <Info className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--primary))]" aria-hidden="true" />
                <p>
                  Choose the cloud provider you want to onboard and identify the account.
                  CloudGuardIQ never receives long-lived credentials — trust is granted by you
                  in the provider console in the next step.
                </p>
              </div>
              <form className="grid gap-3 md:grid-cols-2" onSubmit={startSession}>
                <div className="space-y-1">
                  <label className="text-sm font-medium" htmlFor="provider-select">
                    Provider
                  </label>
                  <select
                    id="provider-select"
                    className="h-10 w-full rounded border px-2 text-sm"
                    value={provider}
                    onChange={(event) =>
                      setProvider(event.target.value as CloudProvider)
                    }
                  >
                    <option value="AZURE">Microsoft Azure</option>
                    <option value="AWS">Amazon Web Services</option>
                    <option value="GCP">Google Cloud Platform</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-sm font-medium" htmlFor="display-name">
                    Display name
                  </label>
                  <input
                    id="display-name"
                    className="h-10 w-full rounded border px-2 text-sm"
                    placeholder="Contoso Production"
                    value={displayName}
                    onChange={(event) => setDisplayName(event.target.value)}
                  />
                </div>

                {provider === "AZURE" && (
                  <div className="space-y-1 md:col-span-2">
                    <label className="text-sm font-medium" htmlFor="tenant-id">
                      Customer tenant ID
                    </label>
                    <input
                      id="tenant-id"
                      className="h-10 w-full rounded border px-2 font-mono text-sm"
                      placeholder="11111111-2222-3333-4444-555555555555"
                      value={tenantId}
                      onChange={(event) => setTenantId(event.target.value)}
                      required
                    />
                    <p className="text-xs text-[hsl(var(--muted-foreground))]">
                      Find this in Azure Portal → Microsoft Entra ID → Overview.
                    </p>
                  </div>
                )}

                {provider === "AWS" && (
                  <div className="space-y-1 md:col-span-2">
                    <label className="text-sm font-medium" htmlFor="account-id">
                      AWS account ID
                    </label>
                    <input
                      id="account-id"
                      className="h-10 w-full rounded border px-2 font-mono text-sm"
                      placeholder="123456789012"
                      value={accountId}
                      onChange={(event) => setAccountId(event.target.value)}
                      required
                    />
                    <p className="text-xs text-[hsl(var(--muted-foreground))]">
                      12-digit account number from AWS Console → My Account.
                    </p>
                  </div>
                )}

                {provider === "AWS" && (
                  <div className="space-y-1 md:col-span-2">
                    <label className="text-sm font-medium" htmlFor="aws-region">
                      AWS region
                    </label>
                    <input
                      id="aws-region"
                      className="h-10 w-full rounded border px-2 font-mono text-sm"
                      placeholder="us-east-1"
                      value={awsRegion}
                      onChange={(event) => setAwsRegion(event.target.value)}
                      pattern="^[a-z]{2}-[a-z]+-\d$"
                      required
                    />
                    <p className="text-xs text-[hsl(var(--muted-foreground))]">
                      Primary region for the connected account, e.g.
                      <code> us-east-1</code> or <code> eu-west-2</code>.
                    </p>
                  </div>
                )}

                {provider === "GCP" && (
                  <div className="space-y-1 md:col-span-2">
                    <label className="text-sm font-medium" htmlFor="project-id">
                      GCP project ID
                    </label>
                    <input
                      id="project-id"
                      className="h-10 w-full rounded border px-2 font-mono text-sm"
                      placeholder="my-prod-project"
                      value={projectId}
                      onChange={(event) => setProjectId(event.target.value)}
                      required
                    />
                    <p className="text-xs text-[hsl(var(--muted-foreground))]">
                      Project ID (not project number) from Google Cloud Console.
                    </p>
                  </div>
                )}

                <div className="md:col-span-2 flex justify-end">
                  <Button type="submit" disabled={busyAction === "create"}>
                    {busyAction === "create" ? "Creating..." : "Create session & continue"}
                  </Button>
                </div>
              </form>
            </section>
          )}

          {step >= 2 && session && (
            <section className="space-y-3 rounded border bg-white p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline">{PROVIDER_LABELS[session.provider]}</Badge>
                <span className="font-medium">{displayName || "(no name)"}</span>
                <span className="text-[hsl(var(--muted-foreground))]">·</span>
                <span className="text-[hsl(var(--muted-foreground))]">Session</span>
                <span className="font-mono text-xs">{session.session_id}</span>
                <Badge variant={statusVariant(session.status)}>{session.status}</Badge>
                <div className="ml-auto">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => void refreshSession()}
                    disabled={busyAction.length > 0}
                  >
                    Refresh
                  </Button>
                </div>
              </div>
            </section>
          )}

          {step === 2 && session && (
            <section className="space-y-4">
              <h3 className="text-base font-semibold">
                Step 2 — Grant trust in {PROVIDER_LABELS[session.provider]}
              </h3>
              {!hasArtifacts && (
                <Alert>
                  <AlertDescription>
                    Click <strong>Generate Artifacts</strong> to produce the provider-specific
                    instructions and links for this session.
                  </AlertDescription>
                </Alert>
              )}

              <div className="flex flex-wrap gap-2">
                <Button
                  onClick={() => void generateArtifacts()}
                  disabled={busyAction.length > 0}
                >
                  {busyAction === "artifacts"
                    ? "Generating..."
                    : hasArtifacts
                      ? "Regenerate Artifacts"
                      : "Generate Artifacts"}
                </Button>
              </div>

              {hasArtifacts && (
                <>
                  <div className="rounded border border-[hsl(var(--primary)/0.3)] bg-[hsl(var(--primary)/0.06)] p-3">
                    <div className="text-sm font-semibold text-[hsl(var(--foreground))]">
                      Apply these steps in {PROVIDER_LABELS[session.provider]}
                    </div>
                    <div className="mt-2 text-[hsl(var(--foreground))]">
                      <ProviderInstructions
                        provider={session.provider}
                        artifacts={session.artifacts}
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="text-sm font-medium">Artifacts</div>
                    <div className="grid gap-2">
                      {Object.entries(session.artifacts).map(([key, value]) => (
                        <ArtifactRow key={key} name={key} value={value} />
                      ))}
                    </div>
                  </div>

                  <div className="flex justify-between">
                    <Button variant="ghost" onClick={() => setStep(1)}>
                      Back
                    </Button>
                    <Button onClick={() => setStep(3)}>
                      I've applied the trust — continue to Verify
                    </Button>
                  </div>
                </>
              )}
            </section>
          )}

          {step === 3 && session && (
            <section className="space-y-4">
              <h3 className="text-base font-semibold">Step 3 — Verify access</h3>
              <p className="text-sm text-[hsl(var(--muted-foreground))]">
                CloudGuardIQ will authenticate to {PROVIDER_LABELS[session.provider]} and run
                three checks: token exchange, permission probe, and scope discovery.
              </p>

              <div className="flex flex-wrap gap-2">
                <Button
                  onClick={() => void verifySession()}
                  disabled={busyAction.length > 0}
                >
                  {busyAction === "verify" ? "Verifying..." : "Run Verification"}
                </Button>
              </div>

              {hasVerification && (
                <div className="grid gap-2 md:grid-cols-3">
                  {session.verification_checks.map((check) => (
                    <div key={check.check} className="rounded border bg-white p-3">
                      <div className="text-sm font-medium">
                        {check.check.replace(/_/g, " ")}
                      </div>
                      <Badge
                        variant={statusVariant(check.status)}
                        className="mt-2"
                      >
                        {check.status}
                      </Badge>
                      {check.message && (
                        <p className="mt-2 text-xs leading-snug text-[hsl(var(--muted-foreground))]">
                          {check.message}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}

              <div className="flex justify-between">
                <Button variant="ghost" onClick={() => setStep(2)}>
                  Back to Trust Setup
                </Button>
                <Button
                  onClick={() => setStep(4)}
                  disabled={!hasScopes}
                >
                  Continue to Connect Scopes
                </Button>
              </div>
            </section>
          )}

          {step === 4 && session && (
            <section className="space-y-4">
              <h3 className="text-base font-semibold">Step 4 — Connect scopes</h3>
              <p className="text-sm text-[hsl(var(--muted-foreground))]">
                Select which {session.provider === "AZURE"
                  ? "subscriptions"
                  : session.provider === "AWS"
                    ? "accounts"
                    : "projects"}{" "}
                CloudGuardIQ should monitor. You can change this later in the Linked
                Subscriptions list.
              </p>

              {hasScopes ? (
                <div className="space-y-2 rounded border p-3">
                  {session.discovered_scopes.map((scope) => (
                    <label
                      key={scope.id}
                      className="flex cursor-pointer items-center justify-between rounded border p-2"
                    >
                      <div>
                        <div className="text-sm font-medium">
                          {scope.display_name || scope.id}
                        </div>
                        <div className="font-mono text-xs text-[hsl(var(--muted-foreground))]">
                          {scope.id}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline">{scope.kind}</Badge>
                        <input
                          type="checkbox"
                          checked={selectedScopeIds.includes(scope.id)}
                          onChange={() => toggleScope(scope.id)}
                        />
                      </div>
                    </label>
                  ))}
                </div>
              ) : (
                <Alert>
                  <AlertDescription>
                    No scopes were discovered yet. Go back to Verify and re-run after trust is
                    applied.
                  </AlertDescription>
                </Alert>
              )}

              <div className="flex justify-between">
                <Button variant="ghost" onClick={() => setStep(3)}>
                  Back to Verify
                </Button>
                <Button
                  onClick={() => void connectScopes()}
                  disabled={
                    busyAction.length > 0 ||
                    !hasScopes ||
                    selectedScopeIds.length === 0
                  }
                >
                  {busyAction === "connect"
                    ? "Connecting..."
                    : `Connect ${selectedScopeIds.length || ""} scope${selectedScopeIds.length === 1 ? "" : "s"}`}
                </Button>
              </div>
            </section>
          )}

          {step === 5 && session && (
            <section className="space-y-4">
              <h3 className="text-base font-semibold">Step 5 — Done</h3>
              <Alert>
                <AlertDescription>
                  {PROVIDER_LABELS[session.provider]} is now connected. CloudGuardIQ will
                  start scanning on the next cycle. You can manage this connection below.
                </AlertDescription>
              </Alert>
              <div className="rounded border bg-white p-3 text-sm">
                <div>
                  <span className="text-[hsl(var(--muted-foreground))]">Connection ID:</span>{" "}
                  <span className="font-mono">{session.connection_id ?? "(pending)"}</span>
                </div>
                <div>
                  <span className="text-[hsl(var(--muted-foreground))]">Scopes connected:</span>{" "}
                  {selectedScopeIds.length}
                </div>
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={resetWizard}>
                  Onboard another provider
                </Button>
              </div>
            </section>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-lg">Cloud Connection Lifecycle</CardTitle>
            <CardDescription>
              Monitor, refresh, and disconnect active provider connections.
            </CardDescription>
          </div>
          <Button
            variant="outline"
            onClick={() => void loadConnections()}
            disabled={connectionsLoading}
          >
            {connectionsLoading ? "Refreshing..." : "Refresh List"}
          </Button>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Provider</TableHead>
                <TableHead>Display Name</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Scopes</TableHead>
                <TableHead>Last Verified</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {connections.map((connection) => (
                <TableRow key={connection.connection_id}>
                  <TableCell>{connection.provider}</TableCell>
                  <TableCell>
                    <div className="font-medium">{connection.display_name}</div>
                    <div className="text-xs text-[hsl(var(--muted-foreground))] font-mono">
                      {connection.connection_id}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={statusVariant(connection.status)}>
                      {connection.status}
                    </Badge>
                  </TableCell>
                  <TableCell>{connection.linked_scopes.length}</TableCell>
                  <TableCell>{isoToLocal(connection.last_verified_at)}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void refreshConnection(connection.connection_id)}
                        disabled={
                          busyAction === `connection-refresh-${connection.connection_id}`
                        }
                      >
                        Refresh
                      </Button>
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() => void disconnectConnection(connection.connection_id)}
                        disabled={
                          busyAction === `connection-delete-${connection.connection_id}`
                        }
                      >
                        Disconnect
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {connections.length === 0 && !connectionsLoading && (
                <TableRow>
                  <TableCell colSpan={6}>
                    <div className="py-6 text-center text-sm text-[hsl(var(--muted-foreground))]">
                      No cloud connections yet. Complete onboarding above to create one.
                    </div>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
