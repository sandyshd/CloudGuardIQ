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

  return { subscriptions, loading, error, refresh, add, remove, rename, toggle };
}
