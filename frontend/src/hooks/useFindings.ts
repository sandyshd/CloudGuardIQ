import { useCallback, useEffect, useState } from "react";
import type { FindingResult } from "../types";
import { getFindings } from "../api/findings";
import { useTimeRange } from "../contexts/TimeRangeContext";

import { toFriendlyMessage } from "../lib/errors";
export function useFindings(subscriptionId?: string, limit = 5000) {
  const [findings, setFindings] = useState<FindingResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { range } = useTimeRange();
  const fromIso = range.from.toISOString();
  // Preset ranges ("Last 24h/7d/30d/90d") mean "from N ago until now". Their
  // upper bound is pinned at render time and only refreshes every 5 minutes,
  // so findings detected by a scan that runs *after* the page loaded would
  // have detected_at > range.to and get filtered out by the backend, blanking
  // the list right after a Run Scan. Only custom ranges carry a real end bound.
  const toIso = range.id === "custom" ? range.to.toISOString() : undefined;

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getFindings(subscriptionId, limit, { from: fromIso, to: toIso });
      setFindings(data);
    } catch (err) {
      setError(toFriendlyMessage(err, "Failed to load findings"));
    } finally {
      setLoading(false);
    }
  }, [subscriptionId, limit, fromIso, toIso]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  /**
   * Merge an updated finding into local state without a network round-trip.
   * Used by optimistic mutations (acknowledge / snooze / resolve) so the list
   * reflects changes immediately, with refresh() acting as eventual consistency.
   */
  const applyUpdate = useCallback((updated: FindingResult) => {
    setFindings((current) =>
      current.map((f) => (f.finding_id === updated.finding_id ? updated : f)),
    );
  }, []);

  return { findings, loading, error, refresh, applyUpdate };
}
