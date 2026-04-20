import { SubscriptionList } from "../components/settings/SubscriptionList";
import { NotificationSettings } from "../components/settings/NotificationSettings";
import { TierSelector } from "../components/settings/TierSelector";

export function Settings() {
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>
      <div className="grid gap-4 md:grid-cols-2">
        <TierSelector />
        <NotificationSettings />
      </div>
      <SubscriptionList />
    </div>
  );
}
