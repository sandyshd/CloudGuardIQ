import { useNavigate } from "react-router-dom";
import type { ReactNode } from "react";
import { Button } from "../ui/button";

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  message: string;
  primaryLabel?: string;
  primaryTo?: string;
  primaryOnClick?: () => void;
  primaryDisabled?: boolean;
  secondary?: ReactNode;
}

export function EmptyState({
  icon,
  title,
  message,
  primaryLabel,
  primaryTo,
  primaryOnClick,
  primaryDisabled,
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

  return (
    <div className="flex flex-col items-center justify-center rounded-[var(--radius)] border border-dashed border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.3)] p-12 text-center">
      {icon ? (
        <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-[hsl(var(--primary)/0.12)] to-[hsl(var(--accent)/0.12)] text-[hsl(var(--primary))] ring-1 ring-[hsl(var(--primary)/0.2)]">
          {icon}
        </div>
      ) : null}
      <h2 className="text-lg font-semibold text-[hsl(var(--foreground))]">
        {title}
      </h2>
      <p className="mt-1 mb-4 max-w-md text-sm text-[hsl(var(--muted-foreground))]">
        {message}
      </p>
      {primaryLabel ? (
        <Button onClick={handleClick} disabled={primaryDisabled}>
          {primaryLabel}
        </Button>
      ) : null}
      {secondary ? <div className="mt-3">{secondary}</div> : null}
    </div>
  );
}
