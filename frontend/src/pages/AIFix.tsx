import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { getRemediation } from "../api/findings";
import { TerraformBlock } from "../components/remediation/TerraformBlock";
import { CLIBlock } from "../components/remediation/CLIBlock";
import { ComplianceImpact } from "../components/remediation/ComplianceImpact";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { Alert, AlertDescription, AlertTitle } from "../components/ui/alert";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import type { RemediationCard } from "../types";

export function AIFix() {
  const [searchParams] = useSearchParams();
  const findingId = searchParams.get("finding");
  const [card, setCard] = useState<RemediationCard | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!findingId) return;
    setLoading(true);
    getRemediation(findingId)
      .then(setCard)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load remediation"))
      .finally(() => setLoading(false));
  }, [findingId]);

  if (!findingId) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold">AI Remediation</h1>
        <Alert>
          <AlertTitle>Select a Finding</AlertTitle>
          <AlertDescription>
            Navigate to Findings and click "Get AI Remediation" on a finding to generate a fix.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (loading) return <LoadingSpinner />;
  if (error) return <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>;
  if (!card) return null;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">AI Remediation</h1>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">Remediation Plan</CardTitle>
            {card.confidence_qualifier && <Badge variant="outline">{card.confidence_qualifier}</Badge>}
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm whitespace-pre-wrap">{card.narrative}</p>
          {card.estimated_savings_usd > 0 && (
            <p className="mt-2 text-sm text-emerald-600 font-medium">
              Estimated savings: ${card.estimated_savings_usd.toFixed(2)}/month
            </p>
          )}
        </CardContent>
      </Card>

      <TerraformBlock code={card.terraform_fix} />
      <CLIBlock command={card.cli_fix} />
      {card.finding_result && (
        <ComplianceImpact frameworks={card.finding_result.compliance_frameworks} />
      )}
    </div>
  );
}
