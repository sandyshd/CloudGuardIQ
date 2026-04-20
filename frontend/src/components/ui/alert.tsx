import { forwardRef, type HTMLAttributes } from "react";
import { cn } from "../../lib/utils";

export interface AlertProps extends HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "destructive";
}

export const Alert = forwardRef<HTMLDivElement, AlertProps>(
  ({ className, variant = "default", ...props }, ref) => (
    <div
      ref={ref}
      role="alert"
      className={cn(
        "relative w-full rounded-lg border p-4",
        variant === "destructive"
          ? "border-[hsl(var(--destructive))] text-[hsl(var(--destructive))]"
          : "bg-[hsl(var(--background))] text-[hsl(var(--foreground))]",
        className
      )}
      {...props}
    />
  )
);
Alert.displayName = "Alert";

export const AlertTitle = forwardRef<HTMLHeadingElement, HTMLAttributes<HTMLHeadingElement>>(
  ({ className, ...props }, ref) => (
    <h5 ref={ref} className={cn("mb-1 font-medium leading-none tracking-tight", className)} {...props} />
  )
);
AlertTitle.displayName = "AlertTitle";

export const AlertDescription = forwardRef<HTMLParagraphElement, HTMLAttributes<HTMLParagraphElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("text-sm [&_p]:leading-relaxed", className)} {...props} />
  )
);
AlertDescription.displayName = "AlertDescription";
