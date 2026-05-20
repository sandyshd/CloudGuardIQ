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

type NoticeKind = "info" | "error";

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
  if (status === "connected" || status === "verified" || status === "active") {
    return "default";
  }
  if (status === "action_required" || status === "failed" || status === "disconnected") {
    return "destructive";
  }
  return "secondary";
}

export function MultiCloudOnboardingHub() {
  const [provider, setProvider] = useState<CloudProvider>("AZURE");
  const [displayName, setDisplayName] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [accountId, setAccountId] = useState("");
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

  async function startSession(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setNotice(null);

    const targetScope =
      provider === "AZURE"
        ? { tenant_id: tenantId.trim() }
        : provider === "AWS"
          ? { account_id: accountId.trim() }
          : { project_id: projectId.trim() };

    setBusyAction("create");
    try {
      const created = await createOnboardingSessionV1({
        provider,
        display_name: displayName.trim(),
        target_scope: targetScope,
      });
      setSession(created);
      setNotice({
        kind: "info",
        message: "Onboarding session created. Continue with artifacts, verify, and connect.",
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
        kind: "info",
        message: "Artifacts generated. Apply trust and permission steps in your provider.",
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
      setNotice({
        kind: "info",
        message: "Verification completed. Select scopes to connect.",
      });
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

    const scopeIds = selectedScopeIds.length > 0
      ? selectedScopeIds
      : discoveredScopeIds;

    if (scopeIds.length === 0) {
      setNotice({
        kind: "error",
        message: "No scopes selected. Run verify first and choose at least one scope.",
      });
      return;
    }

    setBusyAction("connect");
    setNotice(null);
    try {
      const updated = await connectOnboardingSessionV1(session.session_id, scopeIds);
      setSession(updated);
      setNotice({
        kind: "info",
        message: `Connected successfully with connection ID ${updated.connection_id}.`,
      });
      await loadConnections();
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
      setNotice({
        kind: "info",
        message: "Connection refresh completed.",
      });
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
      setNotice({
        kind: "info",
        message: "Cloud connection disconnected.",
      });
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

  const isCreating = busyAction === "create";

  return (
    <div className="space-y-6">
      <Card className="border-blue-200">
        <CardHeader>
          <CardTitle className="text-lg">Multi-Cloud Onboarding</CardTitle>
          <CardDescription>
            Create a provider onboarding session, generate artifacts, verify trust and permissions, then connect discovered scopes.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {notice && (
            <Alert variant={notice.kind === "error" ? "destructive" : "default"}>
              <AlertDescription>{notice.message}</AlertDescription>
            </Alert>
          )}

          <form className="grid gap-3 md:grid-cols-2" onSubmit={startSession}>
            <div className="space-y-1">
              <label className="text-sm font-medium" htmlFor="provider-select">
                Provider
              </label>
              <select
                id="provider-select"
                className="h-10 w-full rounded border px-2 text-sm"
                value={provider}
                onChange={(event) => setProvider(event.target.value as CloudProvider)}
              >
                <option value="AZURE">Azure</option>
                <option value="AWS">AWS</option>
                <option value="GCP">GCP</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="text-sm font-medium" htmlFor="display-name">
                Display Name
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
                  Customer Tenant ID
                </label>
                <input
                  id="tenant-id"
                  className="h-10 w-full rounded border px-2 font-mono text-sm"
                  placeholder="11111111-2222-3333-4444-555555555555"
                  value={tenantId}
                  onChange={(event) => setTenantId(event.target.value)}
                  required
                />
              </div>
            )}

            {provider === "AWS" && (
              <div className="space-y-1 md:col-span-2">
                <label className="text-sm font-medium" htmlFor="account-id">
                  AWS Account ID
                </label>
                <input
                  id="account-id"
                  className="h-10 w-full rounded border px-2 font-mono text-sm"
                  placeholder="123456789012"
                  value={accountId}
                  onChange={(event) => setAccountId(event.target.value)}
                  required
                />
              </div>
            )}

            {provider === "GCP" && (
              <div className="space-y-1 md:col-span-2">
                <label className="text-sm font-medium" htmlFor="project-id">
                  GCP Project ID
                </label>
                <input
                  id="project-id"
                  className="h-10 w-full rounded border px-2 font-mono text-sm"
                  placeholder="my-prod-project"
                  value={projectId}
                  onChange={(event) => setProjectId(event.target.value)}
                  required
                />
              </div>
            )}

            <div className="md:col-span-2 flex justify-end">
              <Button type="submit" disabled={isCreating}>
                {isCreating ? "Creating..." : "Create Session"}
              </Button>
            </div>
          </form>

          {session && (
            <div className="space-y-4 rounded border p-4">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium">Session</span>
                <span className="font-mono text-xs">{session.session_id}</span>
                <Badge variant={statusVariant(session.status)}>{session.status}</Badge>
                {session.connection_id && (
                  <Badge variant="secondary">connection: {session.connection_id}</Badge>
                )}
              </div>

              <div className="flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  onClick={() => void generateArtifacts()}
                  disabled={busyAction.length > 0}
                >
                  Generate Artifacts
                </Button>
                <Button
                  variant="outline"
                  onClick={() => void verifySession()}
                  disabled={busyAction.length > 0}
                >
                  Verify
                </Button>
                <Button
                  onClick={() => void connectScopes()}
                  disabled={busyAction.length > 0 || discoveredScopeIds.length === 0}
                >
                  Connect Selected Scopes
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => void refreshSession()}
                  disabled={busyAction.length > 0}
                >
                  Refresh Session
                </Button>
              </div>

              {Object.keys(session.artifacts).length > 0 && (
                <div className="space-y-2 rounded border bg-[hsl(var(--muted))]/30 p-3">
                  <div className="text-sm font-medium">Artifact Instructions</div>
                  <div className="space-y-2">
                    {Object.entries(session.artifacts).map(([key, value]) => (
                      <div key={key} className="rounded border bg-white p-2">
                        <div className="text-xs uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
                          {key}
                        </div>
                        <textarea
                          value={value}
                          readOnly
                          rows={Math.min(6, Math.max(2, Math.ceil(value.length / 90)))}
                          className="mt-1 w-full resize-y rounded border p-2 font-mono text-xs"
                        />
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {session.verification_checks.length > 0 && (
                <div className="space-y-2 rounded border p-3">
                  <div className="text-sm font-medium">Verification Checks</div>
                  <div className="grid gap-2 md:grid-cols-3">
                    {session.verification_checks.map((check) => (
                      <div key={check.check} className="rounded border p-2 text-sm">
                        <div className="font-medium">{check.check}</div>
                        <Badge variant={statusVariant(check.status)} className="mt-1">
                          {check.status}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {session.discovered_scopes.length > 0 && (
                <div className="space-y-2 rounded border p-3">
                  <div className="text-sm font-medium">Discovered Scopes</div>
                  <div className="space-y-2">
                    {session.discovered_scopes.map((scope) => (
                      <label
                        key={scope.id}
                        className="flex cursor-pointer items-center justify-between rounded border p-2"
                      >
                        <div>
                          <div className="text-sm font-medium">{scope.display_name || scope.id}</div>
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
                </div>
              )}
            </div>
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
                    <Badge variant={statusVariant(connection.status)}>{connection.status}</Badge>
                  </TableCell>
                  <TableCell>{connection.linked_scopes.length}</TableCell>
                  <TableCell>{isoToLocal(connection.last_verified_at)}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void refreshConnection(connection.connection_id)}
                        disabled={busyAction === `connection-refresh-${connection.connection_id}`}
                      >
                        Refresh
                      </Button>
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() => void disconnectConnection(connection.connection_id)}
                        disabled={busyAction === `connection-delete-${connection.connection_id}`}
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
