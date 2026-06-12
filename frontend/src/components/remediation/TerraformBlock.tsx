import { useState } from "react";
import { Button } from "../ui/button";
import { Check, Copy } from "lucide-react";
import { cn } from "../../lib/utils";

interface TokenEntry {
  key: string;
  value: string;
}

function tokenSuffix(index: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let value = index;
  let out = "";
  do {
    out = alphabet[value % 26] + out;
    value = Math.floor(value / 26) - 1;
  } while (value >= 0);
  return out;
}

function createToken(prefix: string, index: number): string {
  return `@@${prefix}_${tokenSuffix(index)}@@`;
}

function restoreTokens(text: string, entries: TokenEntry[]): string {
  return entries.reduce(
    (current, entry) => current.split(entry.key).join(entry.value),
    text,
  );
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Lightweight token-based highlighter so regex passes never touch injected HTML.
function highlightHCL(code: string): string {
  return code
    .split("\n")
    .map((line) => {
      const escapedLine = escapeHtml(line);

      const strings: TokenEntry[] = [];
      const lineWithStringTokens = escapedLine.replace(
        /"([^"\\]|\\.)*"/g,
        (match) => {
          const key = createToken("STR", strings.length);
          strings.push({ key, value: match });
          return key;
        },
      );

      const commentIndex = lineWithStringTokens.indexOf("#");
      const codePart =
        commentIndex >= 0
          ? lineWithStringTokens.slice(0, commentIndex)
          : lineWithStringTokens;
      const commentPart =
        commentIndex >= 0 ? lineWithStringTokens.slice(commentIndex) : "";

      const attributes: TokenEntry[] = [];
      const withAttrTokens = codePart.replace(
        /^(\s*)([a-zA-Z_][\w-]*)(\s*=)/,
        (_full, leading, attr, equalsPart) => {
          const key = createToken("ATTR", attributes.length);
          attributes.push({
            key,
            value: `${leading}<span class="text-violet-300">${attr}</span>${equalsPart}`,
          });
          return key;
        },
      );

      const keywords: TokenEntry[] = [];
      const withKeywordTokens = withAttrTokens.replace(
        /\b(resource|data|variable|output|provider|module|locals|terraform)\b/g,
        (match) => {
          const key = createToken("KW", keywords.length);
          keywords.push({
            key,
            value: `<span class="text-sky-300 font-semibold">${match}</span>`,
          });
          return key;
        },
      );

      const literals: TokenEntry[] = [];
      const withLiteralTokens = withKeywordTokens.replace(
        /\b(true|false|null|\d+(?:\.\d+)?)\b/g,
        (match) => {
          const key = createToken("LIT", literals.length);
          literals.push({
            key,
            value: `<span class="text-amber-300">${match}</span>`,
          });
          return key;
        },
      );

      let highlightedCode = restoreTokens(withLiteralTokens, literals);
      highlightedCode = restoreTokens(highlightedCode, keywords);
      highlightedCode = restoreTokens(highlightedCode, attributes);

      const codeWithStrings = restoreTokens(
        highlightedCode,
        strings.map((entry) => ({
          key: entry.key,
          value: `<span class="text-emerald-300">${entry.value}</span>`,
        })),
      );

      if (!commentPart) {
        return codeWithStrings;
      }

      const commentRaw = restoreTokens(commentPart, strings);
      return `${codeWithStrings}<span class="text-slate-400">${commentRaw}</span>`;
    })
    .join("\n");
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
