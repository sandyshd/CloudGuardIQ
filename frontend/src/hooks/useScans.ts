import { useState } from "react";
import type { ScanResponse } from "../types";
import { triggerScan } from "../api/scans";

import { toFriendlyMessage } from "../lib/errors";
export function useScans() {
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scan = async (subscriptionId: string) => {
    setScanning(true);
    setError(null);
    try {
      const result = await triggerScan({ subscription_id: subscriptionId, include_cost: true });
      setScanResult(result);
      return result;
    } catch (err) {
      setError(toFriendlyMessage(err, "Scan failed"));
      return null;
    } finally {
      setScanning(false);
    }
  };

  return { scanResult, scanning, error, scan };
}
