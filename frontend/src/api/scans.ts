import apiClient from "./client";
import type { ScanRequest, ScanResponse } from "../types";

export async function triggerScan(request: ScanRequest): Promise<ScanResponse> {
  const { data } = await apiClient.post<ScanResponse>("/scan", request);
  return data;
}

export async function getScanStatus(scanId: string): Promise<ScanResponse> {
  const { data } = await apiClient.get<ScanResponse>(`/scans/${scanId}`);
  return data;
}
