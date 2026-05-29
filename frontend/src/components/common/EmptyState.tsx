import { useNavigate } from "react-router-dom";
import type { ReactNode } from "react";
import { BookOpen } from "lucide-react";
import { Button } from "../ui/button";

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  message: string;
  primaryLabel?: string;
  primaryTo?: string;
  primaryOnClick?: () => void;
  primaryDisabled?: boolean;
  /** Optional docs/help URL. Renders as a secondary link beneath the primary CTA. */
  docsHref?: string;
  docsLabel?: string;
  secondary?: ReactNode;
}

const DEFAULT_DOCS_HREF = "https://github.com/sandyshd/CloudGuardIQ#readme";

export function EmptyState({
  icon,
  title,
  message,
  primaryLabel,
  primaryTo,
  primaryOnClick,
  primaryDisabled,
  docsHref,
  docsLabel = "Read the docs",
  secondary,
}: EmptyStateProps) {
  const navigate = useNavigate();
  const handleClick = () => {
    if (primaryOnClick) {
      primaryOnClick();
    } else if (primaryTo) {
      navigate(primaryTo);
    }
  };
  const resolvedDocs = docsHref ?? DEFAULT_DOCS_HREF;

  return (
    <div
      role="status"
      aria-live="polite"
      className="flex flex-col items-center justify-center rounded-[var(--radius)] border border-dashed border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.3)] p-12 text-center"
    >
      {icon ? (
        <div
          aria-hidden
          className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-[hsl(var(--primary)/0.12)] to-[hsl(var(--accent)/0.12)] text-[hsl(var(--primary))] ring-1 ring-[hsl(var(--primary)/0.2)]"
        >
          {icon}
        </div>
      ) : null}
      <h2 className="text-lg font-semibold text-[hsl(var(--foreground))]">
        {title}
      </h2>
      <p className="mt-1 mb-4 max-w-md text-sm text-[hsl(var(--muted-foreground))]">
        {message}
      </p>
      <div className="flex flex-wrap items-center justify-center gap-2">
        {primaryLabel ? (
          <Button
            onClick={handleClick}
            disabled={primaryDisabled}
            className="min-h-[44px]"
          >
            {primaryLabel}
          </Button>
        ) : null}
        <a
          href={resolvedDocs}
          target="_blank"
          rel="noreferrer"
          className="inline-flex min-h-[44px] items-center gap-1.5 rounded-md px-3 text-sm font-medium text-[hsl(var(--primary))] underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))]"
        >
          <BookOpen className="h-4 w-4" aria-hidden />
          {docsLabel}
        </a>
      </div>
      {secondary ? <div className="mt-3">{secondary}</div> : null}
    </div>
  );
}