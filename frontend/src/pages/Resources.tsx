import { useMemo, useState } from "react";
import { useResources } from "../hooks/useResources";
import { useSubscriptions } from "../hooks/useSubscriptions";
import { PageHeader } from "../components/common/PageHeader";
import { EmptyState } from "../components/common/EmptyState";
import { StatCard } from "../components/common/StatCard";
import { ProviderBadge } from "../components/common/ProviderBadge";
import { DataTierBadge } from "../components/common/DataTierBadge";
import { Button } from "../components/ui/button";
import { Alert, AlertDescription } from "../components/ui/alert";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../components/ui/table";
import {
  Boxes,
  DollarSign,
  FolderTree,
  Layers,
  Link2,
  RefreshCw,
  Scan,
  Search,
  X as XIcon,
} from "lucide-react";
import type { ResourceSnapshot } from "../types";

const ALL = "ALL";

function shortType(resourceType: string): string {
  if (!resourceType) return "—";
  return resourceType.includes("/")
    ? resourceType.split("/").slice(1).join("/")
    : resourceType;
}

function formatCost(value: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(value);
}

export function Resources() {
  const [subscriptionFilter, setSubscriptionFilter] = useState<string | "ALL" | "">("");
  const { subscriptions, selected: selectedSub } = useSubscriptions();

  const effectiveSub =
    subscriptionFilter === "ALL"
      ? undefined
      : subscriptionFilter !== ""
        ? subscriptionFilter
        : selectedSub?.subscription_id;

  const { resources, loading, error, refresh } = useResources(effectiveSub);

  const [typeFilter, setTypeFilter] = useState<string>(ALL);
  const [regionFilter, setRegionFilter] = useState<string>(ALL);
  const [search, setSearch] = useState("");

  const typeOptions = useMemo(() => {
    const set = new Set<string>();
    for (const r of resources) if (r.resource_type) set.add(r.resource_type);
    return Array.from(set).sort();
  }, [resources]);

  const regionOptions = useMemo(() => {
    const set = new Set<string>();
    for (const r of resources) if (r.region) set.add(r.region);
    return Array.from(set).sort();
  }, [resources]);

  const stats = useMemo(() => {
    const groups = new Set<string>();
    const types = new Set<string>();
    let monthly = 0;
    for (const r of resources) {
      if (r.resource_group) groups.add(r.resource_group);
      if (r.resource_type) types.add(r.resource_type);
      monthly += r.cost_monthly ?? 0;
    }
    return {
      total: resources.length,
      monthly,
      groups: groups.size,
      types: types.size,
    };
  }, [resources]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return resources.filter((r) => {
      if (typeFilter !== ALL && r.resource_type !== typeFilter) return false;
      if (regionFilter !== ALL && r.region !== regionFilter) return false;
      if (q) {
        const blob = [
          r.resource_name,
          r.resource_type,
          r.resource_group,
          r.region,
          r.id,
          ...Object.entries(r.tags ?? {}).map(([k, v]) => `${k}:${v}`),
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!blob.includes(q)) return false;
      }
      return true;
    });
  }, [resources, typeFilter, regionFilter, search]);

  const hasActiveFilters =
    typeFilter !== ALL || regionFilter !== ALL || search.length > 0;

  if (loading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Resources" subtitle="Loading resources..." />
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <div
              key={i}
              className="h-24 animate-pulse rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--muted))]"
            />
          ))}
        </div>
        <div className="space-y-2">
          {[...Array(8)].map((_, i) => (
            <div key={i} className="h-12 animate-pulse rounded bg-[hsl(var(--muted))]" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Resources"
        subtitle="Inventory of every cloud asset captured by your most recent scan."
        actions={
          <Button variant="outline" size="sm" onClick={() => refresh()} aria-label="Refresh">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
        }
      />

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Summary tiles */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard
          label="Total resources"
          value={stats.total.toLocaleString()}
          icon={<Boxes className="h-4 w-4" />}
          tone="brand"
        />
        <StatCard
          label="Monthly cost"
          value={formatCost(stats.monthly)}
          icon={<DollarSign className="h-4 w-4" />}
          tone="success"
        />
        <StatCard
          label="Resource groups"
          value={stats.groups.toLocaleString()}
          icon={<FolderTree className="h-4 w-4" />}
        />
        <StatCard
          label="Resource types"
          value={stats.types.toLocaleString()}
          icon={<Layers className="h-4 w-4" />}
        />
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
          <input
            aria-label="Search resources"
            placeholder="Search resources..."
            className="h-9 w-64 rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] pl-8 pr-2 text-sm focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <select
          aria-label="Resource type"
          className="h-9 max-w-[220px] truncate rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-2 text-sm focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
        >
          <option value={ALL}>All types</option>
          {typeOptions.map((t) => (
            <option key={t} value={t}>
              {shortType(t)}
            </option>
          ))}
        </select>

        <select
          aria-label="Region"
          className="h-9 max-w-[180px] truncate rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-2 text-sm focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
          value={regionFilter}
          onChange={(e) => setRegionFilter(e.target.value)}
        >
          <option value={ALL}>All regions</option>
          {regionOptions.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>

        <select
          aria-label="Subscription"
          className="h-9 max-w-[200px] truncate rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-2 text-sm focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
          value={subscriptionFilter}
          onChange={(e) => setSubscriptionFilter(e.target.value)}
        >
          <option value="">Active subscription</option>
          <option value="ALL">All subscriptions</option>
          {subscriptions.map((sub) => (
            <option key={sub.subscription_id} value={sub.subscription_id}>
              {sub.display_name || sub.subscription_id}
            </option>
          ))}
        </select>

        {hasActiveFilters && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setTypeFilter(ALL);
              setRegionFilter(ALL);
              setSearch("");
            }}
          >
            <XIcon className="h-3.5 w-3.5" />
            Clear
          </Button>
        )}

        <span className="ml-auto pr-2 text-xs text-[hsl(var(--muted-foreground))]">
          {filtered.length} of {resources.length}
        </span>
      </div>

      {resources.length === 0 && !error ? (
        subscriptions.length === 0 ? (
          <EmptyState
            icon={<Link2 className="h-7 w-7" />}
            title="Link a subscription to start scanning"
            message="Connect a cloud subscription on the Settings page, then run a scan to build your resource inventory."
            primaryLabel="Go to Settings"
            primaryTo="/settings"
          />
        ) : (
          <EmptyState
            icon={<Scan className="h-7 w-7" />}
            title="No resources yet"
            message="Run a scan from the Findings page to discover and inventory your cloud resources."
            primaryLabel="Go to Findings"
            primaryTo="/findings"
          />
        )
      ) : (
        <div className="overflow-hidden rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] shadow-sm">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Resource</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Resource group</TableHead>
                <TableHead>Region</TableHead>
                <TableHead>Tags</TableHead>
                <TableHead className="text-right">Monthly cost</TableHead>
                <TableHead>Cloud</TableHead>
                <TableHead>Tier</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((r: ResourceSnapshot) => {
                const tagEntries = Object.entries(r.tags ?? {});
                return (
                  <TableRow key={r.id}>
                    <TableCell className="font-medium text-[hsl(var(--foreground))]">
                      <span className="block max-w-[260px] truncate" title={r.id || r.resource_name}>
                        {r.resource_name || "—"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span
                        className="block max-w-[200px] truncate text-[hsl(var(--muted-foreground))]"
                        title={r.resource_type}
                      >
                        {shortType(r.resource_type)}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="block max-w-[160px] truncate" title={r.resource_group}>
                        {r.resource_group || "—"}
                      </span>
                    </TableCell>
                    <TableCell className="text-[hsl(var(--muted-foreground))]">
                      {r.region || "—"}
                    </TableCell>
                    <TableCell>
                      {tagEntries.length === 0 ? (
                        <span className="text-[hsl(var(--muted-foreground))]">—</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {tagEntries.slice(0, 2).map(([k, v]) => (
                            <span
                              key={k}
                              className="inline-flex items-center rounded-md bg-[hsl(var(--muted))] px-1.5 py-0.5 text-[10px] font-medium text-[hsl(var(--muted-foreground))]"
                              title={`${k}: ${v}`}
                            >
                              {k}: {v}
                            </span>
                          ))}
                          {tagEntries.length > 2 && (
                            <span className="text-[10px] text-[hsl(var(--muted-foreground))]">
                              +{tagEntries.length - 2}
                            </span>
                          )}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {r.cost_monthly > 0 ? (
                        <span>{formatCost(r.cost_monthly)}</span>
                      ) : (
                        <span className="text-[hsl(var(--muted-foreground))]">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <ProviderBadge provider={r.provider} />
                    </TableCell>
                    <TableCell>
                      <DataTierBadge tier={r.data_tier} />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
