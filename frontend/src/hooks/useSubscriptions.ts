import { useCallback, useEffect, useState } from "react";
import type { Subscription } from "../types";
import {
  addSubscription as apiAdd,
  getSubscriptions,
  removeSubscription as apiRemove,
  renameSubscription as apiRename,
  toggleSubscription as apiToggle,
} from "../api/subscriptions";

export function useSubscriptions() {
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getSubscriptions();
      setSubscriptions(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load subscriptions");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const add = useCallback(
    async (subscription_id: string, display_name = "") => {
      const created = await apiAdd(subscription_id, display_name);
      setSubscriptions((prev) => [...prev, created]);
      return created;
    },
    [],
  );

  const remove = useCallback(async (subscription_id: string) => {
    await apiRemove(subscription_id);
    setSubscriptions((prev) =>
      prev.filter((s) => s.subscription_id !== subscription_id),
    );
  }, []);

  const rename = useCallback(
    async (subscription_id: string, display_name: string) => {
      const updated = await apiRename(subscription_id, display_name);
      setSubscriptions((prev) =>
        prev.map((s) => (s.subscription_id === subscription_id ? updated : s)),
      );
      return updated;
    },
    [],
  );

  // Replace a subscription's ID (and optionally display name) by deleting the
  // old record and adding a new one. Used when the user accidentally linked
  // the wrong subscription GUID. The old record is only removed once the new
  // record has been successfully created so a transient error never leaves
  // the tenant with zero subscriptions.
  const replace = useCallback(
    async (
      old_id: string,
      new_id: string,
      display_name: string,
    ): Promise<Subscription> => {
      if (old_id === new_id) {
        return apiRename(new_id, display_name).then((updated) => {
          setSubscriptions((prev) =>
            prev.map((s) =>
              s.subscription_id === old_id ? updated : s,
            ),
          );
          return updated;
        });
      }
      const created = await apiAdd(new_id, display_name);
      try {
        await apiRemove(old_id);
      } catch (err) {
        // New record exists but old delete failed; surface the error and
        // keep both records visible so the user can retry the delete.
        await refresh();
        throw err;
      }
      setSubscriptions((prev) => [
        ...prev.filter((s) => s.subscription_id !== old_id),
        created,
      ]);
      return created;
    },
    [refresh],
  );

  const toggle = useCallback(
    async (subscription_id: string, state: "Enabled" | "Disabled") => {
      const updated = await apiToggle(subscription_id, state);
      setSubscriptions((prev) =>
        prev.map((s) => (s.subscription_id === subscription_id ? updated : s)),
      );
      return updated;
    },
    [],
  );

  return { subscriptions, loading, error, refresh, add, remove, rename, replace, toggle };
}
