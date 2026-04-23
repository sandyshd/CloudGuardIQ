import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Alert, AlertDescription } from "../ui/alert";
import {
  type BillingStatus,
  type BillingTier,
  createCheckout,
  getBillingStatus,
} from "../../api/billing";
import { cn } from "../../lib/utils";

interface PlanDef {
  tier: BillingTier;
  name: string;
  price: string;
  cadence: string;
  features: string[];
}

const PLANS: PlanDef[] = [
  {
    tier: "FREE",
    name: "Free",
    price: "$0",
    cadence: "/mo",
    features: [
      "1 Azure subscription",
      "Up to 50 resources per scan",
      "Native Tier 1 scanning",
      "Email support",
    ],
  },
  {
    tier: "PRO",
    name: "Pro",
    price: "$49",
    cadence: "/mo",
    features: [
      "Unlimited subscriptions",
      "Unlimited resources per scan",
      "Defender Free CSPM enrichment",
      "AI remediation plans",
    ],
  },
  {
    tier: "ENTERPRISE",
    name: "Enterprise",
    price: "$299",
    cadence: "/mo",
    features: [
      "Everything in Pro",
      "Tier 3 Defender paid plans",
      "Self-healing agents",
      "Priority SLA support",
    ],
  },
];

export function TierSelector() {
  const [status, setStatus] = useState<BillingStatus | null>(null);
  const [busyTier, setBusyTier] = useState<BillingTier | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getBillingStatus()
      .then((s) => {
        if (!cancelled) setStatus(s);
      })
      .catch(() => {
        if (!cancelled) setStatus({ tier: "FREE", stripe_customer_id: "", stripe_subscription_id: "" });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const current = status?.tier ?? "FREE";

  const handleUpgrade = async (tier: BillingTier) => {
    setError(null);
    setBusyTier(tier);
    try {
      const url = await createCheckout(tier);
      window.location.href = url;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to start checkout");
      setBusyTier(null);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Billing Plan</CardTitle>
      </CardHeader>
      <CardContent>
        {error && (
          <Alert variant="destructive" className="mb-3">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <div className="grid gap-3 md:grid-cols-3">
          {PLANS.map((plan) => {
            const isCurrent = plan.tier === current;
            return (
              <div
                key={plan.tier}
                className={cn(
                  "flex flex-col rounded-lg border p-4 transition-shadow",
                  isCurrent
                    ? "border-blue-500 shadow-md ring-1 ring-blue-500"
                    : "border-[hsl(var(--border))]",
                )}
              >
                <div className="flex items-baseline justify-between">
                  <div>
                    <div className="text-sm font-semibold">{plan.name}</div>
                    <div className="text-2xl font-bold">
                      {plan.price}
                      <span className="text-sm font-normal text-[hsl(var(--muted-foreground))]">
                        {plan.cadence}
                      </span>
                    </div>
                  </div>
                  {isCurrent && (
                    <span className="rounded-full bg-blue-100 px-2 py-0.5 text-xs font-semibold text-blue-700">
                      Current
                    </span>
                  )}
                </div>
                <ul className="mt-3 space-y-1 text-xs text-[hsl(var(--muted-foreground))]">
                  {plan.features.map((f) => (
                    <li key={f}>• {f}</li>
                  ))}
                </ul>
                <div className="mt-auto pt-4">
                  {isCurrent ? (
                    <Button variant="outline" className="w-full" disabled>
                      Current Plan
                    </Button>
                  ) : plan.tier === "FREE" ? (
                    <Button variant="outline" className="w-full" disabled>
                      Downgrade in portal
                    </Button>
                  ) : (
                    <Button
                      className="w-full"
                      onClick={() => handleUpgrade(plan.tier)}
                      disabled={busyTier !== null}
                    >
                      {busyTier === plan.tier ? "Redirecting…" : "Upgrade"}
                    </Button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
