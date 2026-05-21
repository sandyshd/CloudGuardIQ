import { type HTMLAttributes } from "react";
import { cn } from "../../lib/utils";

export interface BadgeProps extends HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "secondary" | "destructive" | "outline" | "success" | "warning";
}

const badgeVariants: Record<string, string> = {
  default:
    "bg-[hsl(var(--primary)/0.12)] text-[hsl(var(--primary))] border-transparent",
  secondary:
    "bg-[hsl(var(--secondary))] text-[hsl(var(--secondary-foreground))] border-transparent",
  destructive:
    "bg-[hsl(var(--destructive)/0.12)] text-[hsl(var(--destructive))] border-transparent",
  success:
    "bg-[hsl(var(--success)/0.14)] text-[hsl(var(--success))] border-transparent",
  warning:
    "bg-[hsl(var(--warning)/0.14)] text-[hsl(var(--warning))] border-transparent",
  outline:
    "text-[hsl(var(--foreground))] border-[hsl(var(--border))] bg-transparent",
};

export function Badge({ className, variant = "default", ...props }: BadgeProps) {
  return (
    <div
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide transition-colors",
        badgeVariants[variant],
        className,
      )}
      {...props}
    />
  );
}
