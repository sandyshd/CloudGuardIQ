import { useCallback, useEffect, useState } from "react";
import type { ResourceSnapshot } from "../types";
import { getResources } from "../api/resources";
import { toFriendlyMessage } from "../lib/errors";

/**
 * Fetch the persisted resource snapshots for a subscription. Snapshots are
 * produced by the most recent scan, so this hook reflects the last scan's
 * inventory rather than a live cloud enumeration.
 */
export function useResources(subscriptionId?: string, limit = 1000) {
  const [resources, setResources] = useState<ResourceSnapshot[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getResources(subscriptionId, limit);
      setResources(data);
    } catch (err) {
      setError(toFriendlyMessage(err, "Failed to load resources"));
      setResources([]);
    } finally {
      setLoading(false);
    }
  }, [subscriptionId, limit]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { resources, loading, error, refresh };
}
