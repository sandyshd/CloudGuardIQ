import axios from "axios";
import apiClient from "./client";

export interface AppConfig {
  demo_mode: boolean;
  client_id: string;
  version: string;
}

let _cached: AppConfig | null = null;

export async function getConfig(): Promise<AppConfig> {
  if (_cached) return _cached;
  try {
    const { data } = await apiClient.get<AppConfig>("/config");
    _cached = data;
    return data;
  } catch (err) {
    if (axios.isAxiosError(err)) {
      // Treat config errors as non-demo (production default).
    }
    return { demo_mode: false, client_id: "", version: "" };
  }
}
