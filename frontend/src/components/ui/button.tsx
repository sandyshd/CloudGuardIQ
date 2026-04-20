import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cn } from "../../lib/utils";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "destructive" | "outline" | "secondary" | "ghost" | "link";
  size?: "default" | "sm" | "lg" | "icon";
}

const variantStyles: Record<string, string> = {
  default: "bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] hover:opacity-90",
  destructive: "bg-[hsl(var(--destructive))] text-[hsl(var(--destructive-foreground))] hover:opacity-90",
  outline: "border border-[hsl(var(--input))] bg-transparent hover:bg-[hsl(var(--accent))]",
  secondary: "bg-[hsl(var(--secondary))] text-[hsl(var(--secondary-foreground))] hover:opacity-80",
  ghost: "hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--accent-foreground))]",
  link: "text-[hsl(var(--primary))] underline-offset-4 hover:underline",
};

const sizeStyles: Record<string, string> = {
  default: "h-10 px-4 py-2",
  sm: "h-9 rounded-md px-3",
  lg: "h-11 rounded-md px-8",
  icon: "h-10 w-10",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", ...props }, ref) => (
    <button
      className={cn(
        "inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))] disabled:pointer-events-none disabled:opacity-50",
        variantStyles[variant],
        sizeStyles[size],
        className
      )}
      ref={ref}
      {...props}
    />
  )
);
Button.displayName = "Button";
