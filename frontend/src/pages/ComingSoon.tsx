import { useLocation } from "react-router-dom";
import { Sparkles } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { EmptyState } from "../components/common/EmptyState";

interface RouteMeta {
  title: string;
  subtitle: string;
  description: string;
}

const META: Record<string, RouteMeta> = {
  "/resources": {
    title: "Resources",
    subtitle: "Inventory of every cloud asset under management",
    description:
      "A unified resource inventory across Azure, AWS, and GCP — searchable, filterable, and linked to findings.",
  },
  "/policies": {
    title: "Policies",
    subtitle: "Custom and built-in posture rules",
    description:
      "Author and manage detection rules, exceptions, and severity overrides without touching code.",
  },
  "/finops/optimization": {
    title: "Optimization",
    subtitle: "AI-prioritized cost-saving recommendations",
    description:
      "Right-sizing, idle resource cleanup, reserved-instance coverage, and automated rightsizing PRs.",
  },
  "/finops/budgets": {
    title: "Budgets",
    subtitle: "Spend guardrails and alerts",
    description:
      "Set monthly budgets per subscription, team, or tag and trigger alerts before you overspend.",
  },
  "/integrations": {
    title: "Integrations",
    subtitle: "Connect cloud accounts and downstream tools",
    description:
      "Onboard subscriptions, configure ticketing, SIEM forwarding, and chat notifications.",
  },
  "/reports": {
    title: "Reports",
    subtitle: "Executive summaries and compliance evidence",
    description:
      "Schedulable PDF and CSV exports, board-ready dashboards, and auditor evidence packages.",
  },
  "/audit": {
    title: "Audit Log",
    subtitle: "Every action across the platform",
    description:
      "Full append-only audit trail of remediation actions, policy changes, and access events.",
  },
};

export function ComingSoon() {
  const { pathname } = useLocation();
  const meta = META[pathname] ?? {
    title: "Coming soon",
    subtitle: "This area is in active development",
    description: "Check back shortly — we're building this surface next.",
  };

  return (
    <div className="space-y-6">
      <PageHeader title={meta.title} subtitle={meta.subtitle} />
      <EmptyState
        icon={<Sparkles className="h-7 w-7" />}
        title="Coming soon"
        message={meta.description}
      />
    </div>
  );
}
