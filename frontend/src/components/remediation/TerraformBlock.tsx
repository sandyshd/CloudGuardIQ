import { useState } from "react";
import { Button } from "../ui/button";
import { Check, Copy } from "lucide-react";
import { cn } from "../../lib/utils";

// Lightweight regex-based highlighter so we don't pull in a heavy dep.
function highlightHCL(code: string): string {
  const escape = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  let html = escape(code);
  // Comments
  html = html.replace(/(#.*?$)/gm, '<span class="text-slate-400">$1</span>');
  // Strings
  html = html.replace(/("([^"\\]|\\.)*")/g, '<span class="text-emerald-300">$1</span>');
  // Numbers / booleans
  html = html.replace(/\b(true|false|null|\d+(?:\.\d+)?)\b/g, '<span class="text-amber-300">$1</span>');
  // Block keywords
  html = html.replace(
    /\b(resource|data|variable|output|provider|module|locals|terraform)\b/g,
    '<span class="text-sky-300 font-semibold">$1</span>',
  );
  // Attribute names (word before '=' on a line)
  html = html.replace(
    /^(\s*)([a-zA-Z_][\w-]*)(\s*=)/gm,
    '$1<span class="text-violet-300">$2</span>$3',
  );
  return html;
}

export interface TerraformBlockProps {
  code: string;
  title?: string;
  language?: "hcl" | "bash";
  className?: string;
}

export function TerraformBlock({
  code,
  title = "Terraform Fix",
  language = "hcl",
  className,
}: TerraformBlockProps) {
  const [copied, setCopied] = useState(false);

  if (!code) return null;

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable; no-op */
    }
  };

  const html = language === "hcl" ? highlightHCL(code) : null;

  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-lg border bg-slate-950 text-slate-100 shadow-sm",
        className,
      )}
    >
      <div className="flex items-center justify-between border-b border-slate-800 px-3 py-2">
        <span className="text-xs font-medium uppercase tracking-wide text-slate-400">
          {title}
        </span>
        <Button
          variant="ghost"
          size="sm"
          onClick={onCopy}
          className="h-7 gap-1 px-2 text-slate-200 hover:bg-slate-800 hover:text-white"
          aria-label="Copy code"
        >
          {copied ? (
            <>
              <Check className="h-3.5 w-3.5" /> Copied!
            </>
          ) : (
            <>
              <Copy className="h-3.5 w-3.5" /> Copy
            </>
          )}
        </Button>
      </div>
      <pre className="overflow-x-auto p-4 text-xs leading-relaxed">
        {html !== null ? (
          <code
            className="font-mono"
            dangerouslySetInnerHTML={{ __html: html }}
          />
        ) : (
          <code className="font-mono text-emerald-300">{code}</code>
        )}
      </pre>
    </div>
  );
}
