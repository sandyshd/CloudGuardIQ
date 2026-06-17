import apiClient from "./client";
import type {
  ScanRequest,
  ScanStatusResponse,
  ScanTriggerResponse,
} from "../types";

// Module-level in-flight registry. Any concurrent triggerScan() call
// for the same subscription_id while a scan is already in flight
// returns the original promise instead of issuing a second POST.
const inFlight = new Map<string, Promise<ScanTriggerResponse>>();

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export function isTerminalScanStatus(status: string): boolean {
  return status === "completed" || status === "failed" || status === "timed_out";
}

export async function triggerScan(request: ScanRequest): Promise<ScanTriggerResponse> {
  const key = request.subscription_id;
  const existing = inFlight.get(key);
  if (existing) return existing;

  const promise = apiClient
    .post<ScanTriggerResponse>("/scan/trigger", request)
    .then((res) => res.data)
    .finally(() => {
      inFlight.delete(key);
    });
  inFlight.set(key, promise);
  return promise;
}

export async function getScanStatus(scanId: string): Promise<ScanStatusResponse> {
  const { data } = await apiClient.get<ScanStatusResponse>(`/scan/${scanId}/status`);
  return data;
}

export async function pollScanStatus(
  scanId: string,
  options?: { pollIntervalMs?: number; maxAttempts?: number },
): Promise<ScanStatusResponse> {
  const pollIntervalMs = options?.pollIntervalMs ?? 3000;
  const maxAttempts = options?.maxAttempts ?? 40;
  let last = await getScanStatus(scanId);

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const status = String(last.status || "").toLowerCase();
    if (isTerminalScanStatus(status)) {
      return last;
    }
    // Backward-compat inference for older payloads without explicit status.
    if (!status && Number(last.duration_seconds || 0) > 0) {
      return { ...last, status: "completed" };
    }
    await sleep(pollIntervalMs);
    last = await getScanStatus(scanId);
  }

  return last;
}
