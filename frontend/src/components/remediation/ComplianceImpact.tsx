import { Badge } from "../ui/badge";

export function ComplianceImpact({ frameworks }: { frameworks: string[] }) {
  if (frameworks.length === 0) return null;

  return (
    <div>
      <h4 className="text-sm font-medium mb-2">Compliance Impact</h4>
      <div className="flex gap-1 flex-wrap">
        {frameworks.map((fw) => (
          <Badge key={fw} variant="secondary">{fw}</Badge>
        ))}
      </div>
    </div>
  );
}
