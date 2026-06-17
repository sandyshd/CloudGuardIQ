import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Alert, AlertDescription, AlertTitle } from "../ui/alert";
import { toFriendlyError, type FriendlyError } from "../../lib/errors";
import { Check, Sparkles } from "lucide-react";
import {
  type BillingStatus,
  type BillingTier,
  getBillingStatus,
  selectTier,
} from "../../api/billing";
import { cn } from "../../lib/utils";

interface PlanDef {
  tier: BillingTier;
  name: string;
  price: string;
  cadence: string;
  features: string[];
  highlight?: boolean;
}

const TIER_RANK: Record<BillingTier, number> = {
  FREE: 0,
  PRO: 1,
  ENTERPRISE: 2,
};

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
    highlight: true,
    features: [
      "Up to 3 cloud subscriptions",
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
      "Unlimited subscriptions",
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
  const [error, setError] = useState<FriendlyError | null>(null);

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

  // Billing runs in Stripe-free mode: switching to any plan (up or down) is a
  // direct write, no checkout redirect.
  const handleSelect = async (tier: BillingTier) => {
    setError(null);
    setBusyTier(tier);
    try {
      const updated = await selectTier(tier);
      setStatus(updated);
    } catch (err) {
      setError(toFriendlyError(err, "Unable to change plan. Please try again."));
    } finally {
      setBusyTier(null);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Billing plan</CardTitle>
      </CardHeader>
      <CardContent>
        {error && (
          <Alert
            variant={error.tone === "error" ? "destructive" : "warning"}
            className="mb-3"
          >
            <AlertTitle>{error.title}</AlertTitle>
            <AlertDescription>{error.message}</AlertDescription>
          </Alert>
        )}
        <div className="grid gap-3 md:grid-cols-3">
          {PLANS.map((plan) => {
            const isCurrent = plan.tier === current;
            const cmp = TIER_RANK[plan.tier] - TIER_RANK[current];
            const isUpgrade = cmp > 0;
            return (
              <div
                key={plan.tier}
                className={cn(
                  "relative flex flex-col rounded-[var(--radius)] border bg-[hsl(var(--card))] p-4 transition-shadow",
                  isCurrent
                    ? "border-[hsl(var(--primary))] ring-1 ring-[hsl(var(--primary)/0.3)] shadow-sm"
                    : plan.highlight
                      ? "border-[hsl(var(--primary)/0.4)]"
                      : "border-[hsl(var(--border))]",
                )}
              >
                {plan.highlight && !isCurrent && (
                  <span className="absolute -top-2 right-3 inline-flex items-center gap-1 rounded-full bg-[hsl(var(--primary))] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--primary-foreground))]">
                    <Sparkles className="h-3 w-3" />
                    Popular
                  </span>
                )}
                <div className="flex items-baseline justify-between">
                  <div>
                    <div className="text-sm font-semibold text-[hsl(var(--foreground))]">
                      {plan.name}
                    </div>
                    <div className="mt-1 text-2xl font-bold tabular-nums text-[hsl(var(--foreground))]">
                      {plan.price}
                      <span className="text-sm font-normal text-[hsl(var(--muted-foreground))]">
                        {plan.cadence}
                      </span>
                    </div>
                  </div>
                  {isCurrent && (
                    <span className="rounded-full bg-[hsl(var(--primary)/0.14)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-[hsl(var(--primary))]">
                      Current
                    </span>
                  )}
                </div>
                <ul className="mt-3 space-y-1.5 text-xs text-[hsl(var(--muted-foreground))]">
                  {plan.features.map((f) => (
                    <li key={f} className="flex items-start gap-1.5">
                      <Check className="mt-0.5 h-3 w-3 shrink-0 text-[hsl(var(--success))]" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
                <div className="mt-auto pt-4">
                  {isCurrent ? (
                    <Button variant="outline" className="w-full" disabled>
                      Current plan
                    </Button>
                  ) : isUpgrade ? (
                    <Button
                      className="w-full"
                      onClick={() => handleSelect(plan.tier)}
                      disabled={busyTier !== null}
                    >
                      {busyTier === plan.tier ? "Switching…" : "Upgrade"}
                    </Button>
                  ) : (
                    <Button
                      className="w-full"
                      onClick={() => handleSelect(plan.tier)}
                      disabled={busyTier !== null}
                    >
                      {busyTier === plan.tier ? "Switching…" : "Downgrade"}
                    </Button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
        <p className="mt-3 text-xs text-[hsl(var(--muted-foreground))]">
          All plans auto-detect and use cloud-native security signals when
          available — Microsoft Defender for Cloud (Azure), AWS Security Hub /
          GuardDuty (AWS), and Google Security Command Center (GCP) — at no
          extra charge, no plan upgrade required.
        </p>
      </CardContent>
    </Card>
  );
}
