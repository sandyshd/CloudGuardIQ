import { useCallback, useEffect, useState } from "react";
import { getComplianceScorecard, type FrameworkScore } from "../api/compliance";
import { useTimeRange } from "../contexts/TimeRangeContext";

import { toFriendlyMessage } from "../lib/errors";
export function useComplianceScorecard(subscriptionId?: string) {
  const [scorecard, setScorecard] = useState<FrameworkScore[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { range } = useTimeRange();
  const fromIso = range.from.toISOString();
  const toIso = range.to.toISOString();

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getComplianceScorecard(subscriptionId, { from: fromIso, to: toIso });
      setScorecard(data);
    } catch (err) {
      setError(toFriendlyMessage(err, "Failed to load compliance scorecard"));
      setScorecard([]);
    } finally {
      setLoading(false);
    }
  }, [subscriptionId, fromIso, toIso]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { scorecard, loading, error, refresh };
}
