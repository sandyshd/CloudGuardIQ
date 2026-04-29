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

// Pricing axes intentionally cloud-agnostic: subscriptions, resources,
// scan frequency, AI usage. No vendor capability (Defender, GuardDuty,
// Security Command Center) is gated behind a paywall — those signals are
// auto-detected and used to enrich findings on every plan.
const PLANS: PlanDef[] = [
  {
    tier: "FREE",
    name: "Free",
    price: "$0",
    cadence: "/mo",
    features: [
      "1 cloud subscription / account",
      "Up to 100 resources per scan",
      "Daily scans",
      "5 AI remediation plans / month",
      "Community support",
    ],
  },
  {
    tier: "PRO",
    name: "Starter",
    price: "$49",
    cadence: "/mo",
    features: [
      "Up to 3 cloud subscriptions / accounts",
      "Up to 1,000 resources per scan",
      "Hourly scans",
      "100 AI remediation plans / month",
      "Email support",
    ],
  },
  {
    tier: "ENTERPRISE",
    name: "Enterprise",
    price: "$299",
    cadence: "/mo",
    features: [
      "Unlimited subscriptions / accounts",
      "Unlimited resources per scan",
      "15-minute continuous scans",
      "Unlimited AI remediation plans",
      "Self-healing automation",
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
        if (!cancelled)
          setStatus({ tier: "FREE", stripe_customer_id: "", stripe_subscription_id: "" });
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
        <p className="mt-3 text-xs text-[hsl(var(--muted-foreground))]">
          ✨ All plans auto-detect and use Microsoft Defender for Cloud signals
          when available — no extra charge, no plan upgrade required.
        </p>
      </CardContent>
    </Card>
  );
}
