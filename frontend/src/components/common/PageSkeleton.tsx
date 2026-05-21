import { Skeleton } from "../ui/skeleton";

export function PageSkeleton({ withStats = true }: { withStats?: boolean }) {
  return (
    <div className="space-y-6" role="status" aria-live="polite" aria-label="Loading page">
      {/* PageHeader */}
      <div className="flex items-end justify-between gap-4 border-b border-[hsl(var(--border))] pb-5">
        <div className="space-y-2">
          <Skeleton className="h-7 w-56" />
          <Skeleton className="h-4 w-80" />
        </div>
        <Skeleton className="h-9 w-28" />
      </div>

      {withStats && (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <div
              key={i}
              className="rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-5"
            >
              <Skeleton className="h-3 w-20" />
              <Skeleton className="mt-3 h-7 w-16" />
              <Skeleton className="mt-2 h-3 w-32" />
              <Skeleton className="mt-3 h-8 w-full" />
            </div>
          ))}
        </div>
      )}

      <TableSkeleton rows={6} />
      <span className="sr-only">Loading content…</span>
    </div>
  );
}

export function TableSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="overflow-hidden rounded-[var(--radius)] border border-[hsl(var(--border))]">
      <div className="border-b border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.6)] p-3">
        <Skeleton className="h-4 w-40" />
      </div>
      <div className="divide-y divide-[hsl(var(--border))]">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex items-center gap-4 px-4 py-3">
            <Skeleton className="h-2 w-2 rounded-full" />
            <Skeleton className="h-4 flex-1" />
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-5 w-16 rounded-full" />
            <Skeleton className="h-4 w-20" />
          </div>
        ))}
      </div>
    </div>
  );
}

/** Skeleton mirroring the AIFix / detail layout (two-column with sidebar). */
export function DetailSkeleton() {
  return (
    <div className="space-y-6" role="status" aria-live="polite" aria-label="Loading details">
      <div className="flex items-end justify-between gap-4 border-b border-[hsl(var(--border))] pb-5">
        <div className="space-y-2">
          <Skeleton className="h-7 w-72" />
          <Skeleton className="h-4 w-96" />
        </div>
        <Skeleton className="h-9 w-32" />
      </div>
      <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="space-y-4">
          <div className="rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-5 space-y-3">
            <Skeleton className="h-5 w-40" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-5/6" />
            <Skeleton className="h-4 w-3/4" />
          </div>
          <div className="rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-5 space-y-3">
            <Skeleton className="h-5 w-32" />
            <Skeleton className="h-28 w-full" />
          </div>
          <div className="rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-5 space-y-3">
            <Skeleton className="h-5 w-44" />
            <Skeleton className="h-40 w-full" />
          </div>
        </div>
        <div className="space-y-4">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className="rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-5 space-y-2"
            >
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-6 w-36" />
              <Skeleton className="h-4 w-full" />
            </div>
          ))}
        </div>
      </div>
      <span className="sr-only">Loading…</span>
    </div>
  );
}