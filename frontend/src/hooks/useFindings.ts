import { useState, useEffect, useCallback } from "react";
import type { FindingResult } from "../types";
import { getFindings } from "../api/findings";

export function useFindings(subscriptionId?: string) {
  const [findings, setFindings] = useState<FindingResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getFindings(subscriptionId);
      setFindings(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load findings");
    } finally {
      setLoading(false);
    }
  }, [subscriptionId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { findings, loading, error, refresh };
}
