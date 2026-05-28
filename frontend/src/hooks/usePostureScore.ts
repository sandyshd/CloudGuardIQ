import { useCallback, useEffect, useState } from "react";
import { getPostureScore, type PostureScore } from "../api/posture";
import { useTimeRange } from "../contexts/TimeRangeContext";

import { toFriendlyMessage } from "../lib/errors";
export function usePostureScore(subscriptionId?: string) {
  const [posture, setPosture] = useState<PostureScore | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { range } = useTimeRange();
  const fromIso = range.from.toISOString();
  const toIso = range.to.toISOString();

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getPostureScore(subscriptionId, { from: fromIso, to: toIso });
      setPosture(data);
    } catch (err) {
      setError(toFriendlyMessage(err, "Failed to load posture score"));
      setPosture(null);
    } finally {
      setLoading(false);
    }
  }, [subscriptionId, fromIso, toIso]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { posture, loading, error, refresh };
}
