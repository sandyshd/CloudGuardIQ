import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { SeverityBadge } from "../components/common/SeverityBadge";
import { DataTierBadge } from "../components/common/DataTierBadge";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { CLIBlock } from "../components/remediation/CLIBlock";
import { ComplianceImpact } from "../components/remediation/ComplianceImpact";
import { SimilarFindings } from "../components/remediation/SimilarFindings";
import { TerraformBlock } from "../components/remediation/TerraformBlock";
import {
  applyTerraformFix,
  getFinding,
  getFindings,
  getRemediation,
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

  const [finding, setFinding] = useState<FindingResult | null>(null);
  const [card, setCard] = useState<RemediationCard | null>(null);
  const [similar, setSimilar] = useState<FindingResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [action, setAction] = useState<ActionState>("idle");
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!findingId) return;
    setLoading(true);
    setError(null);
    try {
      const [f, c, all] = await Promise.all([
        getFinding(findingId),
        getRemediation(findingId).catch(() => null),
        getFindings().catch(() => [] as FindingResult[]),
      ]);
      setFinding(f);
      setCard(c);
      setSimilar(all.filter((x) => x.finding_id !== findingId).slice(0, 3));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load finding");
    } finally {
      setLoading(false);
    }
  }, [findingId]);

  useEffect(() => {
    load();
  }, [load]);

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

  if (!findingId) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold">AI Fix</h1>
        <Alert>
          <AlertTitle>Select a finding</AlertTitle>
          <AlertDescription>
            Open a finding from the{" "}
            <Link to="/findings" className="underline">
              Findings
            </Link>{" "}
            page to view its AI remediation plan.
          </AlertDescription>
        </Alert>
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
    setActionMessage(null);
    await applyTerraformFix(finding.finding_id);
    setAction("idle");
    setActionMessage("Terraform apply requested. Tracking in Self-Heal.");
  };
  const onResolve = async () => {
    setAction("resolving");
    setActionMessage(null);
    await markFindingResolved(finding.finding_id);
    setAction("idle");
    setActionMessage("Marked as resolved.");
    navigate("/findings");
  };
  const onSnooze = async () => {
    setAction("snoozing");
    setActionMessage(null);
    await snoozeFinding(finding.finding_id, 7);
    setAction("idle");
    setActionMessage("Snoozed for 7 days.");
  };

  const snap = finding.resource_snapshot;
  const savings =
    card?.estimated_savings_usd ??
    finding.waste_monthly_usd ??
    0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">AI Fix</h1>
        <Link
          to="/findings"
          className="text-sm text-[hsl(var(--muted-foreground))] hover:underline"
        >
          &larr; Back to findings
        </Link>
      </div>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        {/* LEFT COLUMN */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <div className="space-y-2">
                <CardTitle className="text-xl">
                  {snap?.resource_name ?? finding.rule_name ?? finding.rule_id}
                </CardTitle>
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  {snap && <DataTierBadge tier={snap.data_tier} />}
                  <Badge variant="outline">
                    Priority {finding.priority_score.toFixed(0)}
                  </Badge>
                  <Badge variant="secondary">{finding.finding_type}</Badge>
                  {snap?.resource_type && (
                    <span className="text-xs text-[hsl(var(--muted-foreground))]">
                      {snap.resource_type}
                    </span>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <p className="text-sm">{finding.description}</p>
            </CardContent>
          </Card>

          {/* AI narrative */}
          <Card className="border-blue-200 bg-blue-50/60">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-base text-blue-900">
                  AI Narrative
                </CardTitle>
                {card?.confidence_qualifier && (
                  <Badge variant="outline">{card.confidence_qualifier}</Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-blue-950">
              {narrativeParagraphs.length > 0 ? (
                narrativeParagraphs.map((p, i) => <p key={i}>{p}</p>)
              ) : (
                <>
                <p className="italic text-blue-900/70 mb-2">
                  Remediation narrative is not available yet.
                </p>
                <Button
                  size="sm"
                  onClick={async () => {
                    setAction("applying");
                    setActionMessage(null);
                    try {
                      const newCard = await generateRemediation(finding.finding_id);
                      setCard(newCard);
                      setActionMessage("AI remediation generated successfully.");
                    } catch {
                      setActionMessage("AI generation failed. Check that Azure OpenAI is configured.");
                    } finally {
                      setAction("idle");
                    }
                  }}
                  disabled={action !== "idle"}
                >
                  {action === "applying" ? "Generating…" : "Generate AI Remediation"}
                </Button>
                </>
              )}
            </CardContent>
          </Card>

          {/* Business risk */}
          <Card className="border-amber-200 bg-amber-50/60">
            <CardHeader>
              <CardTitle className="text-base text-amber-900">
                Business Risk
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-amber-950">{businessRisk}</p>
            </CardContent>
          </Card>

          {/* Fix plan */}
          <Card className="border-emerald-200 bg-emerald-50/60">
            <CardHeader>
              <CardTitle className="text-base text-emerald-900">
                Fix Plan
              </CardTitle>
            </CardHeader>
            <CardContent>
              {card?.narrative ? (
                <ol className="list-decimal space-y-1 pl-5 text-sm text-emerald-950">
                  {narrativeParagraphs.slice(0, 5).map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              ) : (
                <p className="text-sm italic text-emerald-900/70">
                  A step-by-step plan will appear once AI remediation has run.
                </p>
              )}
            </CardContent>
          </Card>

          {card?.terraform_fix && (
            <TerraformBlock code={card.terraform_fix} title="Terraform Fix" />
          )}
          {card?.cli_fix && (
            <CLIBlock command={card.cli_fix} title="Azure CLI Equivalent" />
          )}

          {/* Action buttons */}
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={onApply}
              disabled={action !== "idle" || !card?.terraform_fix}
            >
              {action === "applying" ? "Applying…" : "Apply Terraform"}
            </Button>
            <Button
              variant="secondary"
              onClick={onResolve}
              disabled={action !== "idle"}
            >
              {action === "resolving" ? "Resolving…" : "Mark resolved"}
            </Button>
            <Button
              variant="outline"
              onClick={onSnooze}
              disabled={action !== "idle"}
            >
              {action === "snoozing" ? "Snoozing…" : "Snooze 7 days"}
            </Button>
          </div>
          {actionMessage && (
            <Alert>
              <AlertDescription>{actionMessage}</AlertDescription>
            </Alert>
          )}
        </div>

        {/* RIGHT COLUMN */}
        <div className="space-y-4">
          <ComplianceImpact frameworks={finding.compliance_frameworks} />

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Cost Savings Projection</CardTitle>
            </CardHeader>
            <CardContent>
              <table className="w-full text-sm">
                <tbody>
                  <tr className="border-b">
                    <td className="py-2 text-[hsl(var(--muted-foreground))]">
                      Monthly savings
                    </td>
                    <td className="py-2 text-right font-semibold text-emerald-600">
                      ${savings.toFixed(2)}
                    </td>
                  </tr>
                  <tr className="border-b">
                    <td className="py-2 text-[hsl(var(--muted-foreground))]">
                      Annualised
                    </td>
                    <td className="py-2 text-right font-semibold text-emerald-600">
                      ${(savings * 12).toFixed(2)}
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2 text-[hsl(var(--muted-foreground))]">
                      Current monthly cost
                    </td>
                    <td className="py-2 text-right">
                      ${(snap?.cost_monthly ?? 0).toFixed(2)}
                    </td>
                  </tr>
                </tbody>
              </table>
            </CardContent>
          </Card>

          <SimilarFindings findings={similar} />
        </div>
      </div>
    </div>
  );
}

