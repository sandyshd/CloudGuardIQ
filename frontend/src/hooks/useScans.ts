import { useState } from "react";
import type { ScanRunStatus, ScanStatusResponse } from "../types";
import { pollScanStatus, triggerScan } from "../api/scans";
import { toFriendlyMessage } from "../lib/errors";

export type ScanPhase = "idle" | "queued" | "running" | "completed" | "failed" | "timed_out";

export function useScans() {
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null);
  const [scanning, setScanning] = useState(false);
  const [phase, setPhase] = useState<ScanPhase>("idle");
  const [error, setError] = useState<string | null>(null);

  const scan = async (subscriptionId: string) => {
    setScanning(true);
    setError(null);
    setPhase("queued");
    try {
      const queued = await triggerScan({
        subscription_id: subscriptionId,
        include_cost: true,
      });
      setPhase("running");
      const finalStatus = await pollScanStatus(queued.scan_id);
      setScanStatus(finalStatus);
      const terminal = String(finalStatus.status || "").toLowerCase() as ScanRunStatus;
      if (terminal === "failed") {
        setPhase("failed");
      } else {
        setPhase("completed");
      }
      return finalStatus;
    } catch (err) {
      setPhase("failed");
      setError(toFriendlyMessage(err, "Scan failed"));
      return null;
    } finally {
      setScanning(false);
    }
  };

  return { scanStatus, scanning, phase, error, scan };
}
