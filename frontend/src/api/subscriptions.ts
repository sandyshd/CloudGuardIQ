import apiClient from "./client";
import type { Subscription } from "../types";

export async function getSubscriptions(): Promise<Subscription[]> {
  const { data } = await apiClient.get<Subscription[]>("/subscriptions");
  return data;
}
