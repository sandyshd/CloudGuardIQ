// Backwards-compatible thin wrapper so existing pages keep working.
// The real state lives in `auth/SubscriptionContext` so all consumers
// share a single subscription list and selected-subscription value.
import { useSubscriptionContext } from "../auth/SubscriptionContext";

export function useSubscriptions() {
  return useSubscriptionContext();
}

export function useSelectedSubscription() {
  const { selected, selectedId, setSelectedId, subscriptions } =
    useSubscriptionContext();
  return { selected, selectedId, setSelectedId, subscriptions };
}
