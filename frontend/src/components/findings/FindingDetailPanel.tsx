import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { SeverityBadge } from "../common/SeverityBadge";
import { DataTierBadge } from "../common/DataTierBadge";
import { SourceBadge } from "../common/SourceBadge";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { useToast } from "../ui/toast";
import {
  Sparkles,
  X,
  Copy,
  Check,
  ExternalLink,
  CheckCircle2,
  Clock,
  CircleSlash,
} from "lucide-react";
import { cn } from "../../lib/utils";
import { markFindingResolved, snoozeFinding } from "../../api/findings";
import type { FindingResult } from "../../types";

interface FindingDetailPanelProps {
  finding: FindingResult;
  onClose: () => void;
  /**
   * Optional callback invoked when the user mutates the finding (resolve,
   * snooze, acknowledge). Updates are applied optimistically — parents should
   * merge the partial into their local list before any network round-trip
   * completes.
   */
  onUpdate?: (next: FindingResult) => void;
}

type TabId = "overview" | "evidence" | "compliance";

const tabs: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "evidence", label: "Evidence" },
  { id: "compliance", label: "Compliance" },
];

function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          /* clipboard unavailable */
        }
      }}
      className="inline-flex items-center gap-1 rounded border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-2 py-1 text-[11px] font-medium text-[hsl(var(--muted-foreground))] transition-colors hover:text-[hsl(var(--foreground))]"
      aria-label={label}
    >
      {done ? <Check className="h-3 w-3 text-[hsl(var(--success))]" /> : <Copy className="h-3 w-3" />}
      {done ? "Copied" : label}
    </button>
  );
}

function MetaRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-[hsl(var(--border))] py-2.5 last:border-b-0">
      <dt className="text-xs font-medium uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
        {label}
      </dt>
      <dd className="min-w-0 max-w-[60%] truncate text-right text-sm text-[hsl(var(--foreground))]">
        {children}
      </dd>
    </div>
  );
}

export function FindingDetailPanel({ finding, onClose, onUpdate }: FindingDetailPanelProps) {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [tab, setTab] = useState<TabId>("overview");
  const [local, setLocal] = useState<FindingResult>(finding);
  const [busy, setBusy] = useState<null | "resolve" | "snooze" | "ack">(null);

  // Keep local copy in sync if the parent swaps the finding while the panel
  // is open (e.g. after a list refresh).
  useEffect(() => {
    setLocal(finding);
  }, [finding]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [onClose]);

  const r = local.resource_snapshot;
  const evidenceText = JSON.stringify(local.evidence ?? {}, null, 2);
  const subscriptionId = r?.subscription_id ?? "";

  async function applyOptimistic(
    kind: "resolve" | "snooze" | "ack",
    patch: Partial<FindingResult>,
    network: () => Promise<FindingResult>,
    successTitle: string,
  ) {
    if (!subscriptionId) {
      toast({
        tone: "error",
        title: "Cannot update finding",
        description: "Missing subscription scope for this finding.",
      });
      return;
    }
    const previous = local;
    const optimistic = { ...local, ...patch };
    setLocal(optimistic);
    onUpdate?.(optimistic);
    setBusy(kind);
    try {
      const server = await network();
      setLocal(server);
      onUpdate?.(server);
      toast({ tone: "success", title: successTitle });
    } catch (err) {
      // Roll back on failure.
      setLocal(previous);
      onUpdate?.(previous);
      const msg = toFriendlyMessage(err, "Request failed");
      toast({ tone: "error", title: "Action failed", description: msg });
    } finally {
      setBusy(null);
    }
  }

  const onResolve = () =>
    applyOptimistic(
      "resolve",
      { status: "RESOLVED" },
      () => markFindingResolved(local.finding_id, subscriptionId),
      "Finding resolved",
    );

  const onSnooze = () =>
    applyOptimistic(
      "snooze",
      { status: "SNOOZED" },
      () => snoozeFinding(local.finding_id, subscriptionId, 7),
      "Snoozed for 7 days",
    );

  // Acknowledge has no backend endpoint yet — keep it optimistic-only and
  // surface it via a transient toast. Persisting acknowledgement would route
  // through a future /findings/{id}/acknowledge call.
  const onAcknowledge = () => {
    const previous = local;
    const next = { ...local, status: local.status === "SNOOZED" ? "SNOOZED" : "OPEN" } as FindingResult;
    setLocal(next);
    onUpdate?.(next);
    toast({
      tone: "default",
      title: "Acknowledged",
      description: "Marked as seen on this device.",
    });
    // No network call; revert nothing.
    void previous;
  };

  const isResolved = local.status === "RESOLVED";
  const isSnoozed = local.status === "SNOOZED";

  return (
    <div className="fixed inset-0 z-50">
      {/* Backdrop */}
      <button
        type="button"
        aria-label="Close"
        onClick={onClose}
        className="absolute inset-0 bg-black/40 backdrop-blur-sm transition-opacity"
      />
      {/* Sheet */}
      <aside
        role="dialog"
        aria-label="Finding details"
        aria-modal="true"
        className="absolute inset-y-0 right-0 flex w-full max-w-[640px] flex-col border-l border-[hsl(var(--border))] bg-[hsl(var(--card))] shadow-2xl"
      >
        {/* Header */}
        <header className="border-b border-[hsl(var(--border))] px-6 pt-5 pb-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={local.severity} />
                <Badge variant="outline">{local.finding_type}</Badge>
                {r?.data_tier && <DataTierBadge tier={r.data_tier} />}
                <SourceBadge ruleId={local.rule_id} showNative />
              </div>
              <h2 className="mt-2 text-lg font-semibold leading-tight tracking-tight text-[hsl(var(--foreground))]">
                {local.rule_name || local.rule_id}
              </h2>
              <p className="mt-1 text-sm text-[hsl(var(--muted-foreground))]">
                {local.description}
              </p>
            </div>
            <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close">
              <X className="h-4 w-4" />
            </Button>
          </div>

          {/* Tabs */}
          <nav className="mt-4 flex gap-1 border-b border-[hsl(var(--border))]" aria-label="Detail tabs">
            {tabs.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id)}
                aria-current={tab === t.id ? "page" : undefined}
                className={cn(
                  "relative -mb-px px-3 py-2 text-sm font-medium transition-colors",
                  tab === t.id
                    ? "text-[hsl(var(--foreground))]"
                    : "text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]",
                )}
              >
                {t.label}
                {tab === t.id && (
                  <span className="absolute inset-x-2 -bottom-px h-[2px] rounded-full bg-[hsl(var(--primary))]" />
                )}
              </button>
            ))}
          </nav>
        </header>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5">
          {tab === "overview" && (
            <div className="space-y-6">
              {local.waste_monthly_usd > 0 && (
                <div className="rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--severity-medium)/0.06)] p-4">
                  <div className="text-xs font-medium uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
                    Estimated waste
                  </div>
                  <div className="mt-1 text-2xl font-semibold tracking-tight text-[hsl(var(--foreground))]">
                    ${local.waste_monthly_usd.toFixed(2)}
                    <span className="ml-1 text-xs font-normal text-[hsl(var(--muted-foreground))]">/ month</span>
                  </div>
                  <div className="text-xs text-[hsl(var(--muted-foreground))]">
                    ~${(local.waste_monthly_usd * 12).toFixed(0)} annualised
                  </div>
                </div>
              )}

              {r && (
                <section>
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                    Resource
                  </h3>
                  <div className="rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-4">
                    <dl>
                      <MetaRow label="Name">{r.resource_name || "—"}</MetaRow>
                      <MetaRow label="Type">
                        <span className="font-mono text-xs">{r.resource_type}</span>
                      </MetaRow>
                      <MetaRow label="Region">{r.region || "—"}</MetaRow>
                      <MetaRow label="Resource group">{r.resource_group || "—"}</MetaRow>
                      <MetaRow label="Subscription">
                        <span className="font-mono text-xs">{r.subscription_id}</span>
                      </MetaRow>
                      <MetaRow label="Data tier">
                        <DataTierBadge tier={r.data_tier} />
                      </MetaRow>
                      <MetaRow label="Monthly cost">
                        ${(r.cost_monthly ?? 0).toFixed(2)}
                      </MetaRow>
                    </dl>
                  </div>
                  {r.id && (
                    <div className="mt-2 flex items-center justify-between gap-2 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.4)] px-3 py-2">
                      <code className="truncate font-mono text-[11px] text-[hsl(var(--muted-foreground))]" title={r.id}>
                        {r.id}
                      </code>
                      <CopyButton value={r.id} label="Copy ID" />
                    </div>
                  )}
                </section>
              )}

              <section>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                  Detection
                </h3>
                <div className="rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-4">
                  <dl>
                    <MetaRow label="Rule">
                      <span className="font-mono text-xs">{local.rule_id}</span>
                    </MetaRow>
                    <MetaRow label="Priority score">
                      <span className="font-mono">{local.priority_score}</span>
                    </MetaRow>
                    <MetaRow label="Detected at">
                      {new Date(local.detected_at).toLocaleString()}
                    </MetaRow>
                    <MetaRow label="Status">
                      <Badge variant={local.status === "RESOLVED" ? "success" : "warning"}>
                        {local.status ?? "OPEN"}
                      </Badge>
                    </MetaRow>
                  </dl>
                </div>
              </section>
            </div>
          )}

          {tab === "evidence" && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                  Evidence payload
                </h3>
                <CopyButton value={evidenceText} label="Copy JSON" />
              </div>
              <pre className="max-h-[60vh] overflow-auto rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.4)] p-3 font-mono text-[11px] leading-relaxed text-[hsl(var(--foreground))]">
{evidenceText}
              </pre>
            </div>
          )}

          {tab === "compliance" && (
            <div className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                Compliance frameworks
              </h3>
              {local.compliance_frameworks.length === 0 ? (
                <div className="rounded-md border border-dashed border-[hsl(var(--border))] p-6 text-center text-sm text-[hsl(var(--muted-foreground))]">
                  This finding is not mapped to any tracked framework.
                </div>
              ) : (
                <ul className="space-y-1">
                  {local.compliance_frameworks.map((fw) => (
                    <li
                      key={fw}
                      className="flex items-center justify-between rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 py-2 text-sm"
                    >
                      <span className="font-medium">{fw}</span>
                      <ExternalLink className="h-3.5 w-3.5 text-[hsl(var(--muted-foreground))]" aria-hidden />
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-[hsl(var(--border))] bg-[hsl(var(--card))] px-6 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={onAcknowledge}
              disabled={busy !== null}
              aria-label="Acknowledge finding"
            >
              <CheckCircle2 className="h-4 w-4" aria-hidden />
              Acknowledge
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={onSnooze}
              disabled={busy !== null || isSnoozed || isResolved}
              aria-label="Snooze finding for 7 days"
            >
              <Clock className="h-4 w-4" aria-hidden />
              {busy === "snooze" ? "Snoozing…" : "Snooze 7d"}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={onResolve}
              disabled={busy !== null || isResolved}
              aria-label="Mark finding as resolved"
            >
              <CircleSlash className="h-4 w-4" aria-hidden />
              {busy === "resolve" ? "Resolving…" : "Resolve"}
            </Button>
          </div>
          <Button onClick={() => navigate(`/ai-fix?finding=${local.finding_id}`)}>
            <Sparkles className="h-4 w-4" aria-hidden />
            Get AI remediation
          </Button>
        </footer>
      </aside>
    </div>
  );
}
import { toFriendlyMessage } from "../../lib/errors";