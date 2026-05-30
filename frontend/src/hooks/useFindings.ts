import { useCallback, useEffect, useState } from "react";
import type { FindingResult } from "../types";
import { getFindings } from "../api/findings";

import { toFriendlyMessage } from "../lib/errors";

// Module-level cache of the last-known findings per subscription, shared across
// every useFindings() instance. A scan seeds this cache (via seed()), so when
// the user navigates to another page that mounts a fresh useFindings(), the new
// instance renders the cached findings immediately instead of flashing empty.
const findingsCache = new Map<string, FindingResult[]>();

// Timestamp of the last seed() per subscription. Cosmos indexes upserts
// asynchronously, so for a few minutes after a scan the GET /findings query can
// return [] even though the rows exist. During this grace window we refuse to
// let a background refresh overwrite freshly-seeded findings with an empty
// result -- otherwise every page would re-blank until the index caught up.
const seedTimes = new Map<string, number>();
const SEED_GRACE_MS = 6 * 60 * 1000;

export function useFindings(subscriptionId?: string, limit = 5000) {
  const cacheKey = subscriptionId ?? "";
  const [findings, setFindings] = useState<FindingResult[]>(
    () => findingsCache.get(cacheKey) ?? [],
  );
  const [loading, setLoading] = useState(!findingsCache.has(cacheKey));
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const key = subscriptionId ?? "";
    // Only show a blocking spinner when we have nothing cached to render.
    if (!findingsCache.has(key)) setLoading(true);
    setError(null);
    try {
      const data = await getFindings(subscriptionId, limit);
      const cached = findingsCache.get(key);
      const withinSeedGrace =
        Date.now() - (seedTimes.get(key) ?? 0) < SEED_GRACE_MS;
      if (
        data.length === 0 &&
        cached !== undefined &&
        cached.length > 0 &&
        withinSeedGrace
      ) {
        // Cosmos index still catching up after a recent scan -- keep the
        // seeded findings rather than blanking the page with an empty query.
        return;
      }
      findingsCache.set(key, data);
      setFindings(data);
    } catch (err) {
      setError(toFriendlyMessage(err, "Failed to load findings"));
    } finally {
      setLoading(false);
    }
  }, [subscriptionId, limit]);

  // When the selected subscription changes, immediately show its cached
  // findings (if any) so the list does not flash empty before refresh fills it.
  useEffect(() => {
    setFindings(findingsCache.get(cacheKey) ?? []);
  }, [cacheKey]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  /**
   * Merge an updated finding into local state without a network round-trip.
   * Used by optimistic mutations (acknowledge / snooze / resolve) so the list
   * reflects changes immediately, with refresh() acting as eventual consistency.
   */
  const applyUpdate = useCallback(
    (updated: FindingResult) => {
      setFindings((current) => {
        const next = current.map((f) =>
          f.finding_id === updated.finding_id ? updated : f,
        );
        findingsCache.set(subscriptionId ?? "", next);
        return next;
      });
    },
    [subscriptionId],
  );

  /**
   * Replace the list with findings returned directly by a /scan response, and
   * cache them so the data survives navigation to other pages. Cosmos indexes
   * upserts asynchronously, so the indexed GET /findings query can return [] for
   * several minutes right after a scan persists, blanking the page until the
   * index catches up. The scan response already carries the full findings array,
   * so we seed every page from it immediately and let the periodic refresh
   * reconcile once the index is ready.
   */
  const seed = useCallback(
    (next: FindingResult[]) => {
      const key = subscriptionId ?? "";
      findingsCache.set(key, next);
      seedTimes.set(key, Date.now());
      setFindings(next);
      setLoading(false);
      setError(null);
    },
    [subscriptionId],
  );

  return { findings, loading, error, refresh, applyUpdate, seed };
}
