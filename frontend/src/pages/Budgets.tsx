import { useCallback, useEffect, useMemo, useState } from "react";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { PageHeader } from "../components/common/PageHeader";
import { StatCard } from "../components/common/StatCard";
import { EmptyState } from "../components/common/EmptyState";
import { PageSkeleton } from "../components/common/PageSkeleton";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../components/ui/table";
import {
  createBudget,
  deleteBudget,
  getBudgetStatus,
  listBudgets,
} from "../api/finops";
import { toFriendlyMessage } from "../lib/errors";
import type { Budget, BudgetStatus, BudgetStatusValue } from "../types";
import { Wallet, Plus, Trash2, AlertTriangle } from "lucide-react";

function usd(value: number): string {
  return value.toLocaleString("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  });
}

const STATUS_STYLE: Record<BudgetStatusValue, string> = {
  OK: "bg-[hsl(var(--success)/0.14)] text-[hsl(var(--success))]",
  WARN: "bg-[hsl(var(--warning)/0.14)] text-[hsl(var(--warning))]",
  BREACH: "bg-[hsl(var(--severity-critical)/0.14)] text-[hsl(var(--severity-critical))]",
  PROJECTED_BREACH: "bg-[hsl(var(--warning)/0.14)] text-[hsl(var(--warning))]",
};

const DIMENSIONS = [
  { value: "sub_account", label: "Whole subscription" },
  { value: "service", label: "Service" },
  { value: "tag:team", label: "Tag: team" },
  { value: "tag:app", label: "Tag: app" },
  { value: "tag:environment", label: "Tag: environment" },
  { value: "tag:cost_center", label: "Tag: cost center" },
];

interface BudgetForm {
  name: string;
  dimension: string;
  dimension_value: string;
  amount_monthly: string;
  alert_threshold_pct: string;
}

const EMPTY_FORM: BudgetForm = {
  name: "",
  dimension: "sub_account",
  dimension_value: "",
  amount_monthly: "",
  alert_threshold_pct: "0.8",
};

export function Budgets() {
  const { selected: selectedSub, loading: subsLoading } = useSubscriptions();
  const subId = selectedSub?.subscription_id;

  const [budgets, setBudgets] = useState<Budget[]>([]);
  const [statuses, setStatuses] = useState<BudgetStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<BudgetForm>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    if (!subId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [b, s] = await Promise.all([
        listBudgets(subId),
        getBudgetStatus(subId),
      ]);
      setBudgets(b);
      setStatuses(s);
    } catch (err) {
      setError(toFriendlyMessage(err, "Failed to load budgets"));
    } finally {
      setLoading(false);
    }
  }, [subId]);

  useEffect(() => {
    load();
  }, [load]);

  const statusByName = useMemo(() => {
    const m = new Map<string, BudgetStatus>();
    for (const s of statuses) m.set(s.budget_id, s);
    return m;
  }, [statuses]);

  const summary = useMemo(() => {
    const total = budgets.reduce((sum, b) => sum + b.amount_monthly, 0);
    const breaches = statuses.filter(
      (s) => s.status === "BREACH" || s.status === "PROJECTED_BREACH",
    ).length;
    const actual = statuses.reduce((sum, s) => sum + s.actual_cost, 0);
    return { total, breaches, actual };
  }, [budgets, statuses]);

  const handleSubmit = async () => {
    if (!subId || !form.name || !form.amount_monthly) return;
    setSaving(true);
    setError(null);
    try {
      await createBudget({
        subscription_id: subId,
        name: form.name,
        dimension: form.dimension,
        dimension_value: form.dimension_value,
        amount_monthly: Number(form.amount_monthly),
        alert_threshold_pct: Number(form.alert_threshold_pct) || 0.8,
      });
      setForm(EMPTY_FORM);
      setShowForm(false);
      await load();
    } catch (err) {
      setError(toFriendlyMessage(err, "Failed to save budget"));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (budgetId: string) => {
    setError(null);
    try {
      await deleteBudget(budgetId);
      await load();
    } catch (err) {
      setError(toFriendlyMessage(err, "Failed to delete budget"));
    }
  };

  if (subsLoading || loading) {
    return <PageSkeleton />;
  }

  if (!subId) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Budgets"
          subtitle="Track actual and forecasted spend against monthly budgets."
        />
        <EmptyState
          icon={<Wallet className="h-7 w-7" />}
          title="Select a subscription"
          message="Choose a subscription to create and track budgets."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Budgets"
        subtitle="Track actual and forecasted spend against monthly budgets."
        actions={
          <Button onClick={() => setShowForm((v) => !v)}>
            <Plus className="h-4 w-4" />
            New budget
          </Button>
        }
      />

      {error ? (
        <div className="rounded-[var(--radius)] border border-[hsl(var(--severity-critical)/0.4)] bg-[hsl(var(--severity-critical)/0.08)] p-4 text-sm text-[hsl(var(--severity-critical))]">
          {error}
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <StatCard
          label="Total budgeted"
          value={usd(summary.total)}
          hint={`${budgets.length} budgets`}
          icon={<Wallet className="h-5 w-5" />}
          tone="brand"
        />
        <StatCard
          label="Month-to-date spend"
          value={usd(summary.actual)}
          icon={<Wallet className="h-5 w-5" />}
        />
        <StatCard
          label="Breaches"
          value={summary.breaches}
          hint="actual or projected"
          icon={<AlertTriangle className="h-5 w-5" />}
          tone={summary.breaches > 0 ? "danger" : "success"}
        />
      </div>

      {showForm ? (
        <Card>
          <CardHeader>
            <CardTitle>New budget</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              <label className="flex flex-col gap-1 text-xs text-[hsl(var(--muted-foreground))]">
                Name
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="Production compute"
                  className="h-9 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 text-sm text-[hsl(var(--foreground))]"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-[hsl(var(--muted-foreground))]">
                Dimension
                <select
                  value={form.dimension}
                  onChange={(e) => setForm({ ...form, dimension: e.target.value })}
                  className="h-9 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 text-sm text-[hsl(var(--foreground))]"
                >
                  {DIMENSIONS.map((d) => (
                    <option key={d.value} value={d.value}>
                      {d.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-xs text-[hsl(var(--muted-foreground))]">
                Dimension value
                <input
                  type="text"
                  value={form.dimension_value}
                  onChange={(e) => setForm({ ...form, dimension_value: e.target.value })}
                  placeholder={form.dimension === "sub_account" ? "(whole subscription)" : "e.g. payments"}
                  disabled={form.dimension === "sub_account"}
                  className="h-9 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 text-sm text-[hsl(var(--foreground))] disabled:opacity-50"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-[hsl(var(--muted-foreground))]">
                Monthly amount (USD)
                <input
                  type="number"
                  min={0}
                  value={form.amount_monthly}
                  onChange={(e) => setForm({ ...form, amount_monthly: e.target.value })}
                  placeholder="1000"
                  className="h-9 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 text-sm text-[hsl(var(--foreground))]"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-[hsl(var(--muted-foreground))]">
                Alert threshold (0-1)
                <input
                  type="number"
                  min={0}
                  max={1}
                  step={0.05}
                  value={form.alert_threshold_pct}
                  onChange={(e) => setForm({ ...form, alert_threshold_pct: e.target.value })}
                  className="h-9 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--card))] px-3 text-sm text-[hsl(var(--foreground))]"
                />
              </label>
            </div>
            <div className="mt-4 flex items-center gap-2">
              <Button
                onClick={handleSubmit}
                disabled={saving || !form.name || !form.amount_monthly}
              >
                {saving ? "Saving..." : "Create budget"}
              </Button>
              <Button variant="ghost" onClick={() => { setShowForm(false); setForm(EMPTY_FORM); }}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Budget status</CardTitle>
        </CardHeader>
        <CardContent>
          {budgets.length === 0 ? (
            <EmptyState
              icon={<Wallet className="h-7 w-7" />}
              title="No budgets yet"
              message="Create a budget to start tracking spend against a monthly target."
              primaryLabel="New budget"
              primaryOnClick={() => setShowForm(true)}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead className="text-right">Budget</TableHead>
                  <TableHead className="text-right">MTD</TableHead>
                  <TableHead className="text-right">Projected</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {budgets.map((b) => {
                  const s = statusByName.get(b.budget_id);
                  const status: BudgetStatusValue = s?.status ?? "OK";
                  const scope =
                    b.dimension === "sub_account"
                      ? "Subscription"
                      : `${b.dimension} = ${b.dimension_value || "*"}`;
                  return (
                    <TableRow key={b.budget_id}>
                      <TableCell className="font-medium">{b.name}</TableCell>
                      <TableCell className="text-[hsl(var(--muted-foreground))]">{scope}</TableCell>
                      <TableCell className="text-right">{usd(b.amount_monthly)}</TableCell>
                      <TableCell className="text-right">{usd(s?.actual_cost ?? 0)}</TableCell>
                      <TableCell className="text-right">{usd(s?.projected_month_end_cost ?? 0)}</TableCell>
                      <TableCell>
                        <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_STYLE[status]}`}>
                          {status.replace("_", " ")}
                        </span>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Delete ${b.name}`}
                          onClick={() => handleDelete(b.budget_id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
