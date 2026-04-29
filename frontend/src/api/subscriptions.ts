import apiClient from "./client";
import type { Subscription } from "../types";

export async function getSubscriptions(): Promise<Subscription[]> {
  const { data } = await apiClient.get<Subscription[]>("/subscriptions");
  return data;
}

export async function addSubscription(
  subscription_id: string,
  display_name = "",
): Promise<Subscription> {
  const { data } = await apiClient.post<Subscription>("/subscriptions", {
    subscription_id,
    display_name,
  });
  return data;
}

export async function removeSubscription(subscription_id: string): Promise<void> {
  await apiClient.delete(`/subscriptions/${subscription_id}`);
}

export async function renameSubscription(
  subscription_id: string,
  display_name: string,
): Promise<Subscription> {
  const { data } = await apiClient.patch<Subscription>(
    `/subscriptions/${subscription_id}`,
    { display_name },
  );
  return data;
}

export async function toggleSubscription(
  subscription_id: string,
  state: "Enabled" | "Disabled",
): Promise<Subscription> {
  const { data } = await apiClient.patch<Subscription>(
    `/subscriptions/${subscription_id}`,
    { state },
  );
  return data;
}
