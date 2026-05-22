import { useCallback, useEffect, useState } from "react";
import { getPostureScore, type PostureScore } from "../api/posture";

import { toFriendlyMessage } from "../lib/errors";
export function usePostureScore(subscriptionId?: string) {
  const [posture, setPosture] = useState<PostureScore | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getPostureScore(subscriptionId);
      setPosture(data);
    } catch (err) {
      setError(toFriendlyMessage(err, "Failed to load posture score"));
      setPosture(null);
    } finally {
      setLoading(false);
    }
  }, [subscriptionId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { posture, loading, error, refresh };
}
