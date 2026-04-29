import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { Subscription } from "../types";
import {
  addSubscription as apiAdd,
  getSubscriptions,
  removeSubscription as apiRemove,
  renameSubscription as apiRename,
  toggleSubscription as apiToggle,
} from "../api/subscriptions";

const STORAGE_KEY = "cguardiq.selectedSub";

export interface SubscriptionContextValue {
  subscriptions: Subscription[];
  loading: boolean;
  error: string | null;
  // Currently selected subscription id (lowercase GUID) or null when no
  // Enabled subscriptions are linked. Persisted to localStorage so the
  // user's choice survives page reloads.
  selectedId: string | null;
  selected: Subscription | null;
  setSelectedId: (id: string | null) => void;
  refresh: () => Promise<void>;
  add: (subscription_id: string, display_name?: string) => Promise<Subscription>;
  remove: (subscription_id: string) => Promise<void>;
  rename: (subscription_id: string, display_name: string) => Promise<Subscription>;
  replace: (
    old_id: string,
    new_id: string,
    display_name: string,
  ) => Promise<Subscription>;
  toggle: (
    subscription_id: string,
    state: "Enabled" | "Disabled",
  ) => Promise<Subscription>;
}

const SubscriptionContext = createContext<SubscriptionContextValue | null>(null);

function readPersisted(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function writePersisted(id: string | null): void {
  try {
    if (id) {
      localStorage.setItem(STORAGE_KEY, id);
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // localStorage unavailable (private mode etc.) -- selection becomes
    // session-scoped which is acceptable degraded behaviour.
  }
}

export function SubscriptionProvider({ children }: { children: ReactNode }) {
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedIdState] = useState<string | null>(readPersisted);

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

  // Resolve the effective selection against the loaded list. If the
  // persisted id is gone (sub removed, disabled, or never existed), fall
  // back to the first Enabled subscription. This guarantees pages always
  // see a valid id when at least one Enabled sub is linked.
  const selected = useMemo<Subscription | null>(() => {
    const enabled = subscriptions.filter((s) => s.state === "Enabled");
    if (enabled.length === 0) return null;
    if (selectedId) {
      const match = enabled.find((s) => s.subscription_id === selectedId);
      if (match) return match;
    }
    return enabled[0];
  }, [subscriptions, selectedId]);

  // If the resolved selection differs from the persisted value, write the
  // resolved one back so the URL of truth (localStorage) stays consistent
  // with what the UI actually shows.
  useEffect(() => {
    if (selected && selected.subscription_id !== selectedId) {
      setSelectedIdState(selected.subscription_id);
      writePersisted(selected.subscription_id);
    } else if (!selected && selectedId !== null && !loading) {
      setSelectedIdState(null);
      writePersisted(null);
    }
  }, [selected, selectedId, loading]);

  const setSelectedId = useCallback((id: string | null) => {
    setSelectedIdState(id);
    writePersisted(id);
  }, []);

  const add = useCallback(
    async (subscription_id: string, display_name = "") => {
      const created = await apiAdd(subscription_id, display_name);
      setSubscriptions((prev) => {
        // POST may return a restored soft-deleted record -- replace if it
        // already exists, otherwise append.
        const exists = prev.some((s) => s.subscription_id === created.subscription_id);
        return exists
          ? prev.map((s) =>
              s.subscription_id === created.subscription_id ? created : s,
            )
          : [...prev, created];
      });
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

  const replace = useCallback(
    async (old_id: string, new_id: string, display_name: string) => {
      if (old_id === new_id) {
        const updated = await apiRename(new_id, display_name);
        setSubscriptions((prev) =>
          prev.map((s) => (s.subscription_id === old_id ? updated : s)),
        );
        return updated;
      }
      const created = await apiAdd(new_id, display_name);
      try {
        await apiRemove(old_id);
      } catch (err) {
        await refresh();
        throw err;
      }
      setSubscriptions((prev) => [
        ...prev.filter((s) => s.subscription_id !== old_id),
        created,
      ]);
      // If the removed sub was the selected one, retarget to the new sub.
      if (selectedId === old_id) {
        setSelectedId(created.subscription_id);
      }
      return created;
    },
    [refresh, selectedId, setSelectedId],
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

  const value = useMemo<SubscriptionContextValue>(
    () => ({
      subscriptions,
      loading,
      error,
      selectedId: selected?.subscription_id ?? null,
      selected,
      setSelectedId,
      refresh,
      add,
      remove,
      rename,
      replace,
      toggle,
    }),
    [
      subscriptions,
      loading,
      error,
      selected,
      setSelectedId,
      refresh,
      add,
      remove,
      rename,
      replace,
      toggle,
    ],
  );

  return (
    <SubscriptionContext.Provider value={value}>
      {children}
    </SubscriptionContext.Provider>
  );
}

export function useSubscriptionContext(): SubscriptionContextValue {
  const ctx = useContext(SubscriptionContext);
  if (!ctx) {
    throw new Error(
      "useSubscriptionContext must be used inside <SubscriptionProvider>",
    );
  }
  return ctx;
}
