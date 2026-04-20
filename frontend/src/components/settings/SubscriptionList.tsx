import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { useSubscriptions } from "../../hooks/useSubscriptions";
import { LoadingSpinner } from "../common/LoadingSpinner";

export function SubscriptionList() {
  const { subscriptions, loading } = useSubscriptions();

  if (loading) return <LoadingSpinner />;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Azure Subscriptions</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          {subscriptions.map((sub) => (
            <div key={sub.id} className="flex items-center justify-between rounded border p-3">
              <div>
                <div className="font-medium text-sm">{sub.display_name}</div>
                <div className="text-xs text-[hsl(var(--muted-foreground))]">{sub.id}</div>
              </div>
              <span className="text-xs text-emerald-600">{sub.state}</span>
            </div>
          ))}
          {subscriptions.length === 0 && (
            <p className="text-sm text-[hsl(var(--muted-foreground))]">No subscriptions found</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
