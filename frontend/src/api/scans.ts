import apiClient from "./client";
import type { ScanRequest, ScanResponse } from "../types";

// Module-level in-flight registry. Any concurrent triggerScan() call
// for the same subscription_id while a scan is already in flight
// returns the original promise instead of issuing a second POST. This
// is defence-in-depth: even if the calling component re-renders or
// React 18 StrictMode double-invokes the handler, the network only
// ever sees one /scan request per subscription at a time.
const inFlight = new Map<string, Promise<ScanResponse>>();

export async function triggerScan(request: ScanRequest): Promise<ScanResponse> {
  const key = request.subscription_id;
  const existing = inFlight.get(key);
  if (existing) return existing;

  const promise = apiClient
    .post<ScanResponse>("/scan", request)
    .then((res) => res.data)
    .finally(() => {
      inFlight.delete(key);
    });
  inFlight.set(key, promise);
  return promise;
}

export async function getScanStatus(scanId: string): Promise<ScanResponse> {
  const { data } = await apiClient.get<ScanResponse>(`/scans/${scanId}`);
  return data;
}
