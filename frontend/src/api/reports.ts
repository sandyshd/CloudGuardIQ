import apiClient from "./client";

export interface ReportRecord {
  report_id: string;
  tenant_id?: string;
  subscription_id: string;
  framework_id: string;
  framework_label: string;
  score: number;
  controls_total: number;
  controls_failed: number;
  open_findings: number;
  size_bytes: number;
  blob_name: string;
  download_url: string;
  generated_at: string;
  generated_by?: string;
}

export async function listReports(
  subscriptionId: string,
  limit = 50,
): Promise<ReportRecord[]> {
  const { data } = await apiClient.get<{ reports: ReportRecord[] }>(
    "/reports",
    { params: { subscription_id: subscriptionId, limit } },
  );
  return data.reports;
}

export async function generateReport(
  subscriptionId: string,
  framework = "CIS",
): Promise<ReportRecord> {
  const { data } = await apiClient.get<{ report: ReportRecord }>(
    "/reports/generate",
    { params: { subscription_id: subscriptionId, framework } },
  );
  return data.report;
}

export async function downloadReport(reportId: string): Promise<Blob> {
  const { data } = await apiClient.get<Blob>(`/reports/${reportId}/download`, {
    responseType: "blob",
  });
  return data;
}

export function triggerBrowserDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
