import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";

export function LifecycleGenerator() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Lifecycle Policy Generator</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          Automatically generate storage lifecycle rules based on access patterns.
          Coming soon.
        </p>
      </CardContent>
    </Card>
  );
}
