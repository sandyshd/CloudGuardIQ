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
    <div className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-12 text-center">
      {icon ? (
        <div className="mb-4 text-[hsl(var(--muted-foreground))]">{icon}</div>
      ) : null}
      <h2 className="text-lg font-semibold">{title}</h2>
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
