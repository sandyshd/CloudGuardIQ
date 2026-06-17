import { useCallback, useEffect, useState } from "react";
import type { ResourceSnapshot } from "../types";
import { getResources } from "../api/resources";
import { toFriendlyMessage } from "../lib/errors";

/**
 * Fetch the persisted resource snapshots for a subscription. Snapshots are
 * produced by the most recent scan, so this hook reflects the last scan's
 * inventory rather than a live cloud enumeration.
 *
 * Pass `enabled = false` to defer the request until the caller is ready (for
 * example, while the subscription list is still loading) so the page does not
 * fire a throwaway fetch with an unresolved subscription id.
 */
export function useResources(
  subscriptionId?: string,
  limit = 1000,
  enabled = true,
) {
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
    if (!enabled) {
      // Nothing to fetch yet (e.g. no subscription selected). Clear the initial
      // loading flag so dependent pages can fall through to their empty state
      // instead of being stuck on a skeleton forever.
      setLoading(false);
      return;
    }
    refresh();
  }, [refresh, enabled]);

  return { resources, loading, error, refresh };
}
