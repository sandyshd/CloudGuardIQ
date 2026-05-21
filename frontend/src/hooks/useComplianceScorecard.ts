import { useCallback, useEffect, useState } from "react";
import { getComplianceScorecard, type FrameworkScore } from "../api/compliance";

export function useComplianceScorecard(subscriptionId?: string) {
  const [scorecard, setScorecard] = useState<FrameworkScore[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getComplianceScorecard(subscriptionId);
      setScorecard(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load compliance scorecard");
      setScorecard([]);
    } finally {
      setLoading(false);
    }
  }, [subscriptionId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { scorecard, loading, error, refresh };
}
