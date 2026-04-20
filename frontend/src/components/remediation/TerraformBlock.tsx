import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Copy } from "lucide-react";

export function TerraformBlock({ code }: { code: string }) {
  const copyToClipboard = () => navigator.clipboard.writeText(code);

  if (!code) return null;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm">Terraform Fix</CardTitle>
        <Button variant="ghost" size="icon" onClick={copyToClipboard}><Copy className="h-4 w-4" /></Button>
      </CardHeader>
      <CardContent>
        <pre className="rounded bg-[hsl(var(--muted))] p-4 text-xs overflow-x-auto whitespace-pre-wrap">
          {code}
        </pre>
      </CardContent>
    </Card>
  );
}
