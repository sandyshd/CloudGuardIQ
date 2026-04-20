import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Copy } from "lucide-react";

export function CLIBlock({ command }: { command: string }) {
  const copyToClipboard = () => navigator.clipboard.writeText(command);

  if (!command) return null;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm">CLI Fix</CardTitle>
        <Button variant="ghost" size="icon" onClick={copyToClipboard}><Copy className="h-4 w-4" /></Button>
      </CardHeader>
      <CardContent>
        <pre className="rounded bg-gray-900 text-green-400 p-4 text-xs overflow-x-auto whitespace-pre-wrap font-mono">
          {command}
        </pre>
      </CardContent>
    </Card>
  );
}
