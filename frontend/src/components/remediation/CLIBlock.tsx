import { TerraformBlock } from "./TerraformBlock";

export interface CLIBlockProps {
  command: string;
  title?: string;
}

export function CLIBlock({ command, title = "Azure CLI" }: CLIBlockProps) {
  if (!command) return null;
  return <TerraformBlock code={command} title={title} language="bash" />;
}
