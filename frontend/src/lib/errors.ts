import { isAxiosError } from "axios";

export type FriendlyTone = "warning" | "error" | "info";

export interface FriendlyError {
  title: string;
  message: string;
  tone: FriendlyTone;
  actionLabel?: string;
  actionHref?: string;
}

interface QuotaDetail {
  error?: string;
  current_tier?: string;
  limit?: string;
  cap?: number | string;
  current?: number | string;
}

function prettyLimit(s: string | undefined): string {
  if (!s) return "this feature";
  return s.replace(/_/g, " ");
}

function titleCase(s: string | undefined): string {
  if (!s) return "";
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}

/** Convert any thrown value into a user-friendly error shape. */
export function toFriendlyError(
  err: unknown,
  fallback = "Something went wrong. Please try again.",
): FriendlyError {
  if (isAxiosError(err)) {
    const status = err.response?.status;
    const detail = err.response?.data?.detail;

    // No response at all -> network / CORS / DNS / offline.
    if (!err.response) {
      return {
        title: "Cannot reach the service",
        message:
          "Check your connection and try again. If this keeps happening, the API may be temporarily unavailable.",
        tone: "warning",
      };
    }

    if (status === 401) {
      return {
        title: "Sign-in required",
        message: "Your session has expired. Please sign in again to continue.",
        tone: "warning",
      };
    }

    // Plan / quota enforcement (FastAPI billing middleware returns 402).
    if (status === 402) {
      const d: QuotaDetail = typeof detail === "object" && detail ? detail : {};
      if (d.error === "upgrade_required") {
        const limitLabel = prettyLimit(d.limit);
        const used = d.current ?? "?";
        const cap = d.cap ?? "?";
        const tier = titleCase(d.current_tier) || "current";
        return {
          title: "Plan limit reached",
          message: `You've used ${used} of ${cap} ${limitLabel} on the ${tier} plan. Upgrade to keep going.`,
          tone: "warning",
          actionLabel: "View plans",
          actionHref: "/settings",
        };
      }
      return {
        title: "Upgrade required",
        message:
          typeof detail === "string"
            ? detail
            : "This feature is not available on your current plan.",
        tone: "warning",
        actionLabel: "View plans",
        actionHref: "/settings",
      };
    }

    if (status === 403) {
      return {
        title: "Permission required",
        message:
          typeof detail === "string"
            ? detail
            : "You don't have permission to perform this action.",
        tone: "warning",
      };
    }

    if (status === 404) {
      return {
        title: "Not found",
        message:
          typeof detail === "string"
            ? detail
            : "We couldn't find what you were looking for.",
        tone: "warning",
      };
    }

    if (status === 409) {
      return {
        title: "Conflict",
        message:
          typeof detail === "string"
            ? detail
            : "That action conflicts with the current state. Refresh and try again.",
        tone: "warning",
      };
    }

    if (status === 429) {
      return {
        title: "Too many requests",
        message: "Please slow down and try again in a moment.",
        tone: "warning",
      };
    }

    if (status === 502 || status === 503 || status === 504) {
      const detailStr = typeof detail === "string" ? detail : "";
      if (/stripe/i.test(detailStr)) {
        return {
          title: "Billing service unavailable",
          message:
            "We couldn't reach the billing provider right now. Please try again in a few minutes.",
          tone: "warning",
        };
      }
      if (/openai|ai engine/i.test(detailStr)) {
        return {
          title: "AI service unavailable",
          message:
            "The AI remediation service is temporarily unavailable. Please retry shortly.",
          tone: "warning",
        };
      }
      return {
        title: "Service temporarily unavailable",
        message:
          "An upstream service didn't respond. Please try again in a moment.",
        tone: "warning",
      };
    }

    if (status && status >= 500) {
      return {
        title: "Server error",
        message:
          "Something went wrong on our side. We've logged the issue — please try again.",
        tone: "error",
      };
    }

    if (typeof detail === "string" && detail) {
      return { title: "Request failed", message: detail, tone: "warning" };
    }

    if (detail && typeof detail === "object" && "message" in detail && typeof (detail as { message: unknown }).message === "string") {
      return {
        title: "Request failed",
        message: (detail as { message: string }).message,
        tone: "warning",
      };
    }
  }

  // Plain Error / unknown — hide axios stock strings.
  if (err instanceof Error && err.message) {
    if (/^Request failed with status code/i.test(err.message)) {
      return { title: "Request failed", message: fallback, tone: "warning" };
    }
    return { title: "Request failed", message: err.message, tone: "warning" };
  }

  return { title: "Request failed", message: fallback, tone: "warning" };
}

/** Convenience wrapper for places that only need a string message. */
export function toFriendlyMessage(err: unknown, fallback?: string): string {
  return toFriendlyError(err, fallback).message;
}
export function formatScanTimestamp(value: string): string {
  // Render an ISO timestamp as "YYYY-MM-DD HH:MM:SS" in local time.
  // Falls back to the raw value when it cannot be parsed.
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

/**
 * Friendly message for a /scan failure. For a 429 scan-frequency rejection it
 * spells out the plan cap, how long to wait, and the last scan time instead of
 * the generic "please slow down" text. Shared by the Findings and Overview
 * pages so both surface the same scan-cooldown guidance.
 */
export function formatScanError(err: unknown): string {
  const anyErr = err as {
    response?: { status?: number; data?: { detail?: unknown } };
    message?: string;
  };
  const status = anyErr?.response?.status;
  const detail = anyErr?.response?.data?.detail;
  if (status === 429 && detail && typeof detail === "object") {
    const d = detail as Record<string, unknown>;
    const tier = String(d.current_tier ?? "free");
    const cap = Number(d.cap ?? 0);
    const retry = Number(d.retry_after_seconds ?? 0);
    const minutes = Math.ceil(retry / 60);
    const wait =
      retry < 60
        ? `${retry}s`
        : minutes < 60
          ? `${minutes}m`
          : `${Math.ceil(minutes / 60)}h`;
    const last = typeof d.last_event_at === "string" ? d.last_event_at : "";
    const lastSuffix = last ? ` (last scan: ${formatScanTimestamp(last)})` : "";
    return `Your ${tier} plan allows one scan every ${cap} minute${cap === 1 ? "" : "s"}. Try again in ${wait}${lastSuffix}, or upgrade for more frequent scans.`;
  }
  if (typeof detail === "string") return detail;
  if (err instanceof Error) return err.message;
  return "Scan failed";
}

