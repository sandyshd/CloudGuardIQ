import { useState, useEffect } from "react";
import type { Subscription } from "../types";
import { getSubscriptions } from "../api/subscriptions";

export function useSubscriptions() {
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await getSubscriptions();
        setSubscriptions(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load subscriptions");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return { subscriptions, loading, error };
}
