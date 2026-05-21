import { Skeleton } from "../ui/skeleton";

export function PageSkeleton({ withStats = true }: { withStats?: boolean }) {
  return (
    <div className="space-y-6">
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
