import type { ReactNode } from "react";
import { ArrowDownRight, ArrowUpRight, Minus } from "lucide-react";
import { cn } from "../../lib/utils";

type Tone = "default" | "danger" | "warning" | "success" | "brand";

interface StatCardProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  delta?: { value: number; label?: string; goodDirection?: "up" | "down" };
  icon?: ReactNode;
  tone?: Tone;
  sparkline?: number[];
}

const toneIconBg: Record<Tone, string> = {
  default: "bg-[hsl(var(--muted))] text-[hsl(var(--foreground))]",
  brand: "bg-[hsl(var(--primary)/0.12)] text-[hsl(var(--primary))]",
  danger: "bg-[hsl(var(--severity-critical)/0.12)] text-[hsl(var(--severity-critical))]",
  warning: "bg-[hsl(var(--warning)/0.14)] text-[hsl(var(--warning))]",
  success: "bg-[hsl(var(--success)/0.14)] text-[hsl(var(--success))]",
};

function Sparkline({ points }: { points: number[] }) {
  if (!points || points.length < 2) return null;
  const min = Math.min(...points);
  const max = Math.max(...points);
  const range = max - min || 1;
  const w = 100;
  const h = 32;
  const step = w / (points.length - 1);
  const d = points
    .map((p, i) => {
      const x = i * step;
      const y = h - ((p - min) / range) * h;
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const area = `${d} L${w},${h} L0,${h} Z`;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-8 w-full" preserveAspectRatio="none" aria-hidden>
      <path d={area} fill="hsl(var(--primary) / 0.12)" />
      <path d={d} fill="none" stroke="hsl(var(--primary))" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function StatCard({ label, value, hint, delta, icon, tone = "default", sparkline }: StatCardProps) {
  const goodDir = delta?.goodDirection ?? "up";
  const isFlat = !delta || delta.value === 0;
  const isPositive = !isFlat && (goodDir === "up" ? delta!.value > 0 : delta!.value < 0);
  const DeltaIcon = isFlat ? Minus : delta!.value > 0 ? ArrowUpRight : ArrowDownRight;
  const deltaColor = isFlat
    ? "text-[hsl(var(--muted-foreground))]"
    : isPositive
      ? "text-[hsl(var(--success))]"
      : "text-[hsl(var(--severity-critical))]";

  return (
    <div className="group relative overflow-hidden rounded-[var(--radius)] border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-5 shadow-sm transition-shadow hover:shadow-md">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-xs font-medium uppercase tracking-wide text-[hsl(var(--muted-foreground))]">
            {label}
          </div>
          <div className="mt-2 text-[1.75rem] font-semibold leading-none tracking-tight text-[hsl(var(--foreground))]">
            {value}
          </div>
        </div>
        {icon ? (
          <div className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-lg", toneIconBg[tone])}>
            {icon}
          </div>
        ) : null}
      </div>

      <div className="mt-3 flex items-center gap-2 text-xs">
        {delta ? (
          <span className={cn("inline-flex items-center gap-0.5 font-medium", deltaColor)}>
            <DeltaIcon className="h-3.5 w-3.5" />
            {Math.abs(delta.value).toFixed(1)}%
          </span>
        ) : null}
        {hint ? <span className="text-[hsl(var(--muted-foreground))]">{hint}</span> : null}
      </div>

      {sparkline && sparkline.length > 1 ? (
        <div className="mt-3 -mx-1">
          <Sparkline points={sparkline} />
        </div>
      ) : null}
    </div>
  );
}
