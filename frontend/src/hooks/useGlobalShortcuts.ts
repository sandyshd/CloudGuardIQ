import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";

interface Options {
  onOpenPalette: () => void;
  onOpenHelp: () => void;
}

const GO_TARGETS: Record<string, string> = {
  f: "/findings",
  r: "/resources",
  o: "/",
  c: "/compliance",
  s: "/settings",
  i: "/integrations",
  a: "/ai-fix",
  p: "/policies",
  h: "/self-heal",
};

const GO_PREFIX_TIMEOUT_MS = 1500;

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  if (target.isContentEditable) return true;
  return false;
}

/**
 * Registers global keyboard shortcuts:
 *   - Cmd/Ctrl+K -> command palette
 *   - ?          -> shortcuts help
 *   - g <x>      -> navigate (f=findings, r=resources, o=overview, ...)
 *
 * Shortcuts are suppressed while typing in inputs / contentEditable.
 */
export function useGlobalShortcuts({ onOpenPalette, onOpenHelp }: Options): void {
  const navigate = useNavigate();
  const pendingGo = useRef<number | null>(null);

  useEffect(() => {
    function clearGo() {
      if (pendingGo.current !== null) {
        window.clearTimeout(pendingGo.current);
        pendingGo.current = null;
      }
    }

    function onKey(e: KeyboardEvent) {
      // Cmd+K / Ctrl+K — always honored.
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        clearGo();
        onOpenPalette();
        return;
      }

      // Skip remaining shortcuts when typing or when any modifier is held.
      if (isTypingTarget(e.target) || e.metaKey || e.ctrlKey || e.altKey) {
        return;
      }

      // ? — open help (Shift+/ on US layouts).
      if (e.key === "?") {
        e.preventDefault();
        clearGo();
        onOpenHelp();
        return;
      }

      // Two-key "go to" sequence: press g, then a target letter.
      if (pendingGo.current !== null) {
        const target = GO_TARGETS[e.key.toLowerCase()];
        clearGo();
        if (target) {
          e.preventDefault();
          navigate(target);
        }
        return;
      }
      if (e.key.toLowerCase() === "g") {
        e.preventDefault();
        pendingGo.current = window.setTimeout(() => {
          pendingGo.current = null;
        }, GO_PREFIX_TIMEOUT_MS);
      }
    }

    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      clearGo();
    };
  }, [navigate, onOpenPalette, onOpenHelp]);
}