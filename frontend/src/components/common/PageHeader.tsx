import type { ReactNode } from "react";

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  meta?: ReactNode;
}

/**
 * Consistent page header used at the top of every route.
 * Renders title + optional subtitle, with optional right-aligned actions
 * and an optional meta row underneath (badges, breadcrumbs, scope chips).
 */
export function PageHeader({ title, subtitle, actions, meta }: PageHeaderProps) {
  return (
    <header className="flex flex-col gap-3 border-b border-[hsl(var(--border))] pb-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[1.625rem] font-semibold leading-tight tracking-tight text-[hsl(var(--foreground))]">
            {title}
          </h1>
          {subtitle ? (
            <p className="mt-1 text-sm text-[hsl(var(--muted-foreground))] text-balance">
              {subtitle}
            </p>
          ) : null}
        </div>
        {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
      </div>
      {meta ? <div className="flex flex-wrap items-center gap-2">{meta}</div> : null}
    </header>
  );
}
