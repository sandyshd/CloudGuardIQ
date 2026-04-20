import { type HTMLAttributes } from "react";
import { cn } from "../../lib/utils";

export interface BadgeProps extends HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "secondary" | "destructive" | "outline";
}

const badgeVariants: Record<string, string> = {
  default: "bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))]",
  secondary: "bg-[hsl(var(--secondary))] text-[hsl(var(--secondary-foreground))]",
  destructive: "bg-[hsl(var(--destructive))] text-[hsl(var(--destructive-foreground))]",
  outline: "text-[hsl(var(--foreground))] border",
};

export function Badge({ className, variant = "default", ...props }: BadgeProps) {
  return (
    <div
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors",
        badgeVariants[variant],
        className
      )}
      {...props}
    />
  );
}
