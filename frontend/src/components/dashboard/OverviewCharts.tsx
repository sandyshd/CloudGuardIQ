import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  LabelList,
} from "recharts";
import type { FindingResult, Severity } from "../../types";

const SEV_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "hsl(var(--severity-critical))",
  HIGH: "hsl(var(--severity-high))",
  MEDIUM: "hsl(var(--severity-medium))",
  LOW: "hsl(var(--severity-low))",
  INFORMATIONAL: "hsl(var(--severity-info))",
};

function dayKey(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export function FindingsOverTimeChart({
  findings,
  days = 30,
}: {
  findings: FindingResult[];
  days?: number;
}) {
  const buckets: Record<string, Record<Severity, number>> = {};
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    buckets[dayKey(d)] = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFORMATIONAL: 0,
    };
  }
  findings.forEach((f) => {
    const k = f.detected_at?.slice(0, 10);
    if (k && buckets[k]) {
      buckets[k][f.severity] = (buckets[k][f.severity] || 0) + 1;
    }
  });
  const data = Object.entries(buckets).map(([date, sev]) => ({
    date: date.slice(5),
    CRITICAL: sev.CRITICAL,
    HIGH: sev.HIGH,
    MEDIUM: sev.MEDIUM,
    LOW: sev.LOW,
  }));

  return (
    <ResponsiveContainer width="100%" height={260}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
        <defs>
          {SEV_ORDER.map((s) => (
            <linearGradient id={`g-${s}`} key={s} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={SEV_COLOR[s]} stopOpacity={0.55} />
              <stop offset="100%" stopColor={SEV_COLOR[s]} stopOpacity={0.05} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid stroke="hsl(var(--border))" strokeDasharray="3 3" vertical={false} />
        <XAxis
          dataKey="date"
          tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
          tickLine={false}
          axisLine={{ stroke: "hsl(var(--border))" }}
          interval="preserveStartEnd"
          minTickGap={24}
        />
        <YAxis
          tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
          tickLine={false}
          axisLine={false}
          allowDecimals={false}
          width={32}
        />
        <Tooltip
          contentStyle={{
            background: "hsl(var(--popover))",
            border: "1px solid hsl(var(--border))",
            borderRadius: "var(--radius)",
            fontSize: 12,
          }}
        />
        {SEV_ORDER.map((s) => (
          <Area
            key={s}
            type="monotone"
            dataKey={s}
            stackId="1"
            stroke={SEV_COLOR[s]}
            fill={`url(#g-${s})`}
            strokeWidth={1.5}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function CostByServiceChart({
  data,
  onSelect,
}: {
  data: { service: string; cost: number }[];
  onSelect?: (service: string) => void;
}) {
  if (data.length === 0) {
    return (
      <p className="py-12 text-center text-sm text-[hsl(var(--muted-foreground))]">
        No cost data available yet.
      </p>
    );
  }
  return (
    <ResponsiveContainer width="100%" height={Math.max(220, data.length * 32)}>
      <BarChart
        data={data}
        layout="vertical"
        margin={{ top: 4, right: 48, left: 8, bottom: 4 }}
      >
        <CartesianGrid stroke="hsl(var(--border))" strokeDasharray="3 3" horizontal={false} />
        <XAxis
          type="number"
          tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
          tickLine={false}
          axisLine={false}
          tickFormatter={(v: number) => `$${v.toFixed(0)}`}
        />
        <YAxis
          type="category"
          dataKey="service"
          tick={{ fontSize: 11, fill: "hsl(var(--foreground))" }}
          tickLine={false}
          axisLine={false}
          width={140}
        />
        <Tooltip
          cursor={{ fill: "hsl(var(--accent) / 0.1)" }}
          contentStyle={{
            background: "hsl(var(--popover))",
            border: "1px solid hsl(var(--border))",
            borderRadius: "var(--radius)",
            fontSize: 12,
          }}
          formatter={(v: number) => [`$${v.toFixed(2)}/mo`, "Cost"]}
        />
        <Bar
          dataKey="cost"
          fill="hsl(var(--primary))"
          radius={[0, 4, 4, 0]}
          onClick={(d: { service?: string }) => d.service && onSelect?.(d.service)}
          cursor={onSelect ? "pointer" : "default"}
        >
          <LabelList
            dataKey="cost"
            position="right"
            formatter={(v: number) => `$${v.toFixed(0)}`}
            style={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
          />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function Sparkline({
  values,
  color = "hsl(var(--primary))",
  width = 120,
  height = 36,
}: {
  values: number[];
  color?: string;
  width?: number;
  height?: number;
}) {
  if (values.length < 2) return null;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const stepX = width / (values.length - 1);
  const points = values
    .map((v, i) => `${(i * stepX).toFixed(1)},${(height - ((v - min) / range) * height).toFixed(1)}`)
    .join(" ");
  const areaPath =
    `M0,${height} ` +
    values
      .map(
        (v, i) =>
          `L${(i * stepX).toFixed(1)},${(height - ((v - min) / range) * height).toFixed(1)}`,
      )
      .join(" ") +
    ` L${width},${height} Z`;
  return (
    <svg width={width} height={height} className="overflow-visible">
      <path d={areaPath} fill={color} fillOpacity={0.12} />
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function ProgressRing({
  value,
  size = 64,
  stroke = 6,
  label,
}: {
  value: number;
  size?: number;
  stroke?: number;
  label: string;
}) {
  const v = Math.max(0, Math.min(100, value));
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const dash = (v / 100) * c;
  const color =
    v >= 80
      ? "hsl(var(--success))"
      : v >= 60
        ? "hsl(var(--severity-medium))"
        : "hsl(var(--severity-critical))";
  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="hsl(var(--border))"
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={`${dash} ${c}`}
          strokeLinecap="round"
        />
      </svg>
      <div className="text-center">
        <div className="text-sm font-semibold leading-none text-[hsl(var(--foreground))]">{v}%</div>
        <div className="mt-1 text-[11px] text-[hsl(var(--muted-foreground))]">{label}</div>
      </div>
    </div>
  );
}
