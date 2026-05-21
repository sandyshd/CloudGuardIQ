import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  Sparkles,
  Link2,
  ArrowLeft,
  AlertTriangle,
  ShieldCheck,
  Wrench,
  CheckCircle2,
  Clock,
} from "lucide-react";
import { EmptyState } from "../components/common/EmptyState";
import { PageHeader } from "../components/common/PageHeader";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { SeverityBadge } from "../components/common/SeverityBadge";
import { DataTierBadge } from "../components/common/DataTierBadge";
import { Alert, AlertDescription } from "../components/ui/alert";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { useToast } from "../components/ui/toast";
import { CLIBlock } from "../components/remediation/CLIBlock";
import { ComplianceImpact } from "../components/remediation/ComplianceImpact";
import { SimilarFindings } from "../components/remediation/SimilarFindings";
import { TerraformBlock } from "../components/remediation/TerraformBlock";
import {
  applyTerraformFix,
  getFinding,
  getFindings,
  markFindingResolved,
  snoozeFinding,
  generateRemediation,
} from "../api/findings";
import type { FindingResult, RemediationCard } from "../types";

type ActionState = "idle" | "applying" | "resolving" | "snoozing";

function splitParagraphs(text: string | undefined): string[] {
  if (!text) return [];
  return text
    .split(/\n{2,}/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function AIFix() {
  const { id: routeId } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const queryId = searchParams.get("finding");
  const findingId = routeId ?? queryId ?? null;
  const navigate = useNavigate();
  const { subscriptions, selected: selectedSub } = useSubscriptions();
  const { toast } = useToast();

  const [finding, setFinding] = useState<FindingResult | null>(null);
  const [card, setCard] = useState<RemediationCard | null>(null);
  const [similar, setSimilar] = useState<FindingResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [action, setAction] = useState<ActionState>("idle");
  const [generating, setGenerating] = useState(false);
  const [generationError, setGenerationError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!findingId) return;
    setLoading(true);
    setError(null);
    try {
      const [f, all] = await Promise.all([
        getFinding(findingId, selectedSub?.subscription_id),
        getFindings(selectedSub?.subscription_id).catch(
          () => [] as FindingResult[],
        ),
      ]);
      setFinding(f);
      setSimilar(all.filter((x) => x.finding_id !== findingId).slice(0, 3));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load finding");
    } finally {
      setLoading(false);
    }
  }, [findingId, selectedSub?.subscription_id]);

  useEffect(() => {
    load();
  }, [load]);

  const runGenerate = useCallback(async () => {
    if (!findingId) return;
    setGenerating(true);
    setGenerationError(null);
    try {
      const newCard = await generateRemediation(findingId);
      setCard(newCard);
    } catch (err) {
      setGenerationError(
        err instanceof Error
          ? err.message
          : "AI generation failed. Check that Azure OpenAI is configured.",
      );
    } finally {
      setGenerating(false);
    }
  }, [findingId]);

  useEffect(() => {
    if (finding && !card && !generating && !generationError) {
      runGenerate();
    }
  }, [finding, card, generating, generationError, runGenerate]);

  const narrativeParagraphs = useMemo(
    () => splitParagraphs(card?.narrative),
    [card?.narrative],
  );

  const businessRisk = useMemo(() => {
    if (!finding) return "";
    const severity = finding.severity;
    const waste = finding.waste_monthly_usd;
    const parts: string[] = [];
    if (severity === "CRITICAL" || severity === "HIGH") {
      parts.push(
        `A ${severity.toLowerCase()} exposure increases the likelihood of a security incident and associated audit findings.`,
      );
    }
    if (waste > 0) {
      parts.push(
        `Estimated $${waste.toFixed(2)} per month is currently wasted until this is addressed.`,
      );
    }
    if (finding.compliance_frameworks.length > 0) {
      parts.push(
        `Impacts compliance with: ${finding.compliance_frameworks.join(", ")}.`,
      );
    }
    return parts.join(" ") || "No material business impact detected yet.";
  }, [finding]);

  // No finding selected
  if (!findingId) {
    if (subscriptions.length === 0) {
      return (
        <div className="space-y-6">
          <PageHeader
            title="AI Remediation"
            subtitle="Generate Terraform and CLI fix plans for any finding."
          />
          <EmptyState
            icon={<Link2 className="h-12 w-12" />}
            title="Link a subscription to start scanning"
            message="AI Remediation generates Terraform and CLI plans for findings produced by a scan. Connect an Azure subscription on the Settings page to begin."
            primaryLabel="Go to Settings"
            primaryTo="/settings"
          />
        </div>
      );
    }
    return (
      <div className="space-y-6">
        <PageHeader
          title="AI Remediation"
          subtitle="Generate Terraform and CLI fix plans for any finding."
        />
        <EmptyState
          icon={<Sparkles className="h-12 w-12" />}
          title="Select a finding"
          message="Open a finding from the Findings page to view its AI-generated remediation plan, Terraform fix, and CLI commands."
          primaryLabel="Go to Findings"
          primaryTo="/findings"
        />
      </div>
    );
  }

  if (loading && !finding) return <LoadingSpinner />;
  if (error) {
    return (
      <Alert variant="destructive">
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }
  if (!finding) return null;

  const onApply = async () => {
    setAction("applying");
    await applyTerraformFix(
      finding.finding_id,
      finding.resource_snapshot?.subscription_id ?? "",
    );
    setAction("idle");
    toast({ tone: "success", title: "Terraform apply requested", description: "Tracking in Self-Heal." });
  };
  const onResolve = async () => {
    setAction("resolving");
    await markFindingResolved(
      finding.finding_id,
      finding.resource_snapshot?.subscription_id ?? "",
    );
    setAction("idle");
    toast({ tone: "success", title: "Finding resolved" });
    navigate("/findings");
  };
  const onSnooze = async () => {
    setAction("snoozing");
    await snoozeFinding(
      finding.finding_id,
      finding.resource_snapshot?.subscription_id ?? "",
      7,
    );
    setAction("idle");
    toast({ tone: "default", title: "Snoozed for 7 days" });
  };

  const snap = finding.resource_snapshot;
  const savings =
    card?.estimated_savings_usd ?? finding.waste_monthly_usd ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Remediation"
        subtitle={snap?.resource_name ?? finding.rule_name ?? finding.rule_id}
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate("/findings")}
          >
            <ArrowLeft className="h-4 w-4" />
            Back to findings
          </Button>
        }
        meta={
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <Badge variant="outline">{finding.finding_type}</Badge>
            {snap && <DataTierBadge tier={snap.data_tier} />}
            <Badge variant="secondary">
              Priority {finding.priority_score.toFixed(0)}
            </Badge>
            {snap?.resource_type && (
              <span className="font-mono text-xs text-[hsl(var(--muted-foreground))]">
                {snap.resource_type}
              </span>
            )}
          </div>
        }
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        {/* LEFT COLUMN */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Finding</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-[hsl(var(--foreground))]">
                {finding.description}
              </p>
              {snap && (
                <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-3">
                  <div>
                    <dt className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                      Region
                    </dt>
                    <dd className="text-[13px]">{snap.region || "—"}</dd>
                  </div>
                  <div>
                    <dt className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                      Resource group
                    </dt>
                    <dd className="text-[13px]">{snap.resource_group || "—"}</dd>
                  </div>
                  <div>
                    <dt className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--muted-foreground))]">
                      Monthly cost
                    </dt>
                    <dd className="text-[13px] tabular-nums">
                      ${(snap.cost_monthly ?? 0).toFixed(2)}
                    </dd>
                  </div>
                </dl>
              )}
            </CardContent>
          </Card>

          {/* AI narrative */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-[hsl(var(--primary))]" />
                  <CardTitle>AI narrative</CardTitle>
                </div>
                {card?.confidence_qualifier && (
                  <Badge variant="outline">{card.confidence_qualifier}</Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="space-y-2 text-sm leading-relaxed text-[hsl(var(--foreground))]">
              {narrativeParagraphs.length > 0 ? (
                narrativeParagraphs.map((p, i) => <p key={i}>{p}</p>)
              ) : generating ? (
                <div className="flex items-center gap-2 text-[hsl(var(--muted-foreground))]">
                  <Sparkles className="h-4 w-4 animate-pulse text-[hsl(var(--primary))]" />
                  Generating AI remediation… this can take a few seconds.
                </div>
              ) : generationError ? (
                <>
                  <p className="text-[hsl(var(--severity-critical))]">
                    {generationError}
                  </p>
                  <Button size="sm" onClick={runGenerate} disabled={generating}>
                    Retry generation
                  </Button>
                </>
              ) : (
                <p className="italic text-[hsl(var(--muted-foreground))]">
                  Preparing AI remediation…
                </p>
              )}
            </CardContent>
          </Card>

          {/* Business risk */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-[hsl(var(--warning))]" />
                <CardTitle>Business risk</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-[hsl(var(--foreground))]">
                {businessRisk}
              </p>
            </CardContent>
          </Card>

          {/* Fix plan */}
          {narrativeParagraphs.length > 0 && (
            <Card>
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Wrench className="h-4 w-4 text-[hsl(var(--success))]" />
                  <CardTitle>Fix plan</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <ol className="list-decimal space-y-1.5 pl-5 text-sm text-[hsl(var(--foreground))]">
                  {narrativeParagraphs.slice(0, 5).map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              </CardContent>
            </Card>
          )}

          {card?.terraform_fix && (
            <TerraformBlock code={card.terraform_fix} title="Terraform fix" />
          )}
          {card?.cli_fix && (
            <CLIBlock command={card.cli_fix} title="Azure CLI equivalent" />
          )}

          {/* Actions */}
          <div className="flex flex-wrap items-center gap-2 rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-3 shadow-sm">
            <Button
              onClick={onApply}
              disabled={action !== "idle" || !card?.terraform_fix}
            >
              <Wrench className="h-4 w-4" />
              {action === "applying" ? "Applying…" : "Apply Terraform"}
            </Button>
            <Button
              variant="secondary"
              onClick={onResolve}
              disabled={action !== "idle"}
            >
              <CheckCircle2 className="h-4 w-4" />
              {action === "resolving" ? "Resolving…" : "Mark resolved"}
            </Button>
            <Button
              variant="outline"
              onClick={onSnooze}
              disabled={action !== "idle"}
            >
              <Clock className="h-4 w-4" />
              {action === "snoozing" ? "Snoozing…" : "Snooze 7 days"}
            </Button>
          </div>
        </div>

        {/* RIGHT COLUMN */}
        <div className="space-y-4">
          {/* Savings hero */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-[hsl(var(--success))]" />
                <CardTitle>Cost savings projection</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border border-[hsl(var(--success)/0.3)] bg-[hsl(var(--success)/0.06)] p-4">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--success))]">
                  Monthly savings if applied
                </div>
                <div className="mt-1 text-2xl font-semibold tabular-nums text-[hsl(var(--foreground))]">
                  ${savings.toFixed(2)}
                </div>
              </div>
              <dl className="mt-3 space-y-2 text-sm">
                <div className="flex items-center justify-between">
                  <dt className="text-[hsl(var(--muted-foreground))]">
                    Annualized
                  </dt>
                  <dd className="font-semibold tabular-nums text-[hsl(var(--success))]">
                    ${(savings * 12).toFixed(2)}
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-[hsl(var(--muted-foreground))]">
                    Current monthly cost
                  </dt>
                  <dd className="tabular-nums">
                    ${(snap?.cost_monthly ?? 0).toFixed(2)}
                  </dd>
                </div>
              </dl>
            </CardContent>
          </Card>

          <ComplianceImpact frameworks={finding.compliance_frameworks} />
          <SimilarFindings findings={similar} />
        </div>
      </div>
    </div>
  );
}

