import { useCallback, useEffect, useState } from "react";
import { FileText, Download, Loader2, AlertCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import {
  downloadReport,
  generateReport,
  listReports,
  triggerBrowserDownload,
  type ReportRecord,
} from "../../api/reports";
import { useTimeRange } from "../../contexts/TimeRangeContext";

interface ReportHistoryProps {
  subscriptionId?: string;
  /** Default framework id to generate when the button is clicked. */
  framework?: string;
}

const FRAMEWORK_LABELS: Record<string, string> = {
  CIS_AZURE: "CIS Azure",
  NIST_800_53: "NIST 800-53",
  ISO_27001: "ISO 27001",
  PCI_DSS: "PCI DSS",
  SOC2: "SOC 2",
  HIPAA: "HIPAA",
};

function formatBytes(bytes: number): string {
  if (!bytes) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function ReportHistory({
  subscriptionId,
  framework = "CIS",
}: ReportHistoryProps) {
  const { range } = useTimeRange();
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    if (!subscriptionId) {
      setReports([]);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const rows = await listReports(subscriptionId);
      setReports(rows);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load reports");
    } finally {
      setLoading(false);
    }
  }, [subscriptionId]);

  useEffect(() => {
    reload();
  }, [reload]);

  const handleGenerate = async () => {
    if (!subscriptionId) return;
    setGenerating(true);
    setError(null);
    try {
      await generateReport(subscriptionId, framework, {
        from: range.from.toISOString(),
        to: range.to.toISOString(),
      });
      await reload();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to generate report",
      );
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (report: ReportRecord) => {
    setDownloadingId(report.report_id);
    try {
      const blob = await downloadReport(report.report_id);
      const filename = `${report.framework_id.toLowerCase()}-${report.report_id.slice(0, 8)}.pdf`;
      triggerBrowserDownload(blob, filename);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to download report",
      );
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <CardTitle>Report history</CardTitle>
        <button
          type="button"
          onClick={handleGenerate}
          disabled={!subscriptionId || generating}
          className="inline-flex items-center gap-2 rounded-md bg-[hsl(var(--primary))] px-3 py-1.5 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {generating ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <FileText className="h-4 w-4" />
          )}
          {generating ? "Generating…" : "Generate PDF report"}
        </button>
      </CardHeader>
      <CardContent>
        {error && (
          <div className="mb-3 flex items-center gap-2 rounded-md border border-[hsl(var(--destructive)/0.4)] bg-[hsl(var(--destructive)/0.08)] p-3 text-sm text-[hsl(var(--destructive))]">
            <AlertCircle className="h-4 w-4" />
            {error}
          </div>
        )}
        {loading ? (
          <div className="flex items-center gap-2 text-sm text-[hsl(var(--muted-foreground))]">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading reports…
          </div>
        ) : reports.length === 0 ? (
          <div className="flex items-center gap-3 rounded-md border border-dashed border-[hsl(var(--border))] bg-[hsl(var(--muted)/0.4)] p-4 text-sm text-[hsl(var(--muted-foreground))]">
            <FileText className="h-4 w-4 shrink-0" />
            {subscriptionId
              ? "No reports generated yet. Click ‘Generate PDF report’ to create one."
              : "Select a subscription to generate compliance reports."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase text-[hsl(var(--muted-foreground))]">
                <tr>
                  <th className="px-2 py-2">Framework</th>
                  <th className="px-2 py-2">Score</th>
                  <th className="px-2 py-2">Open findings</th>
                  <th className="px-2 py-2">Generated</th>
                  <th className="px-2 py-2">Size</th>
                  <th className="px-2 py-2 text-right">Download</th>
                </tr>
              </thead>
              <tbody>
                {reports.map((r) => (
                  <tr
                    key={r.report_id}
                    className="border-t border-[hsl(var(--border))]"
                  >
                    <td className="px-2 py-2 font-medium">
                      {r.framework_label ||
                        FRAMEWORK_LABELS[r.framework_id] ||
                        r.framework_id}
                    </td>
                    <td className="px-2 py-2">{r.score}%</td>
                    <td className="px-2 py-2">{r.open_findings}</td>
                    <td className="px-2 py-2 text-[hsl(var(--muted-foreground))]">
                      {formatDate(r.generated_at)}
                    </td>
                    <td className="px-2 py-2 text-[hsl(var(--muted-foreground))]">
                      {formatBytes(r.size_bytes)}
                    </td>
                    <td className="px-2 py-2 text-right">
                      <button
                        type="button"
                        onClick={() => handleDownload(r)}
                        disabled={downloadingId === r.report_id}
                        className="inline-flex items-center gap-1 rounded-md border border-[hsl(var(--border))] px-2 py-1 text-xs hover:bg-[hsl(var(--muted))] disabled:opacity-50"
                      >
                        {downloadingId === r.report_id ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <Download className="h-3 w-3" />
                        )}
                        PDF
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
