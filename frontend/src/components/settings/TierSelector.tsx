import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";

const tiers = [
  { id: "TIER1_NATIVE", name: "Tier 1 — Native", desc: "Azure Resource Graph only (free)" },
  { id: "TIER2_FREE_CSPM", name: "Tier 2 — Free CSPM", desc: "Resource Graph + Defender free tier" },
  { id: "TIER3_PAID", name: "Tier 3 — Paid", desc: "Full Defender for Cloud plans" },
];

export function TierSelector() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Data Source Tier</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {tiers.map((t) => (
            <label key={t.id} className="flex items-start gap-3 rounded border p-3 cursor-pointer hover:bg-[hsl(var(--muted))]">
              <input type="radio" name="tier" value={t.id} className="mt-1" defaultChecked={t.id === "TIER1_NATIVE"} />
              <div>
                <div className="font-medium text-sm">{t.name}</div>
                <div className="text-xs text-[hsl(var(--muted-foreground))]">{t.desc}</div>
              </div>
            </label>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
