import apiClient from "./client";
import type {
  AllocationSummary,
  Budget,
  BudgetStatus,
  SpendAnomaly,
  SpendForecast,
  TagCoverage,
  UnitEconomics,
} from "../types";

/** Showback/chargeback spend grouped by an allocation dimension. */
export async function getAllocation(
  subscriptionId?: string,
  dimension = "team",
): Promise<AllocationSummary> {
  const params: Record<string, string> = { dimension };
  if (subscriptionId) params.subscription_id = subscriptionId;
  const { data } = await apiClient.get<AllocationSummary>(
    "/finops/allocation",
    { params },
  );
  return data;
}

/** Cost-weighted tag-coverage % per default allocation dimension. */
export async function getTagCoverage(
  subscriptionId?: string,
): Promise<TagCoverage> {
  const params: Record<string, string> = {};
  if (subscriptionId) params.subscription_id = subscriptionId;
  const { data } = await apiClient.get<TagCoverage>(
    "/finops/coverage-tags",
    { params },
  );
  return data;
}

/** Statistical spend anomalies over the daily FOCUS series. */
export async function getAnomalies(
  subscriptionId?: string,
  zThreshold = 3.0,
): Promise<SpendAnomaly[]> {
  const params: Record<string, string | number> = { z_threshold: zThreshold };
  if (subscriptionId) params.subscription_id = subscriptionId;
  const { data } = await apiClient.get<SpendAnomaly[]>(
    "/finops/anomalies",
    { params },
  );
  return data;
}

/** Month-to-date + projected cost per tenant-defined unit. */
export async function getUnitEconomics(
  subscriptionId: string | undefined,
  units: number,
  unitLabel = "unit",
): Promise<UnitEconomics> {
  const params: Record<string, string | number> = {
    units,
    unit_label: unitLabel,
  };
  if (subscriptionId) params.subscription_id = subscriptionId;
  const { data } = await apiClient.get<UnitEconomics>(
    "/finops/unit-economics",
    { params },
  );
  return data;
}

/** Projected month-end / next-month spend per allocation key. */
export async function getForecast(
  subscriptionId?: string,
  dimension = "sub_account",
): Promise<SpendForecast[]> {
  const params: Record<string, string> = { dimension };
  if (subscriptionId) params.subscription_id = subscriptionId;
  const { data } = await apiClient.get<SpendForecast[]>(
    "/finops/forecast",
    { params },
  );
  return data;
}

/** List the tenant's budgets, optionally scoped to a subscription. */
export async function listBudgets(
  subscriptionId?: string,
): Promise<Budget[]> {
  const params: Record<string, string> = {};
  if (subscriptionId) params.subscription_id = subscriptionId;
  const { data } = await apiClient.get<Budget[]>("/finops/budgets", {
    params,
  });
  return data;
}

/** Create or update a budget for the caller's tenant. */
export async function createBudget(
  budget: Partial<Budget>,
): Promise<Budget> {
  const { data } = await apiClient.post<Budget>("/finops/budgets", budget);
  return data;
}

/** Delete a budget by id. */
export async function deleteBudget(budgetId: string): Promise<void> {
  await apiClient.delete(`/finops/budgets/${budgetId}`);
}

/** Actual-vs-budget and forecast-vs-budget status per budget. */
export async function getBudgetStatus(
  subscriptionId?: string,
): Promise<BudgetStatus[]> {
  const params: Record<string, string> = {};
  if (subscriptionId) params.subscription_id = subscriptionId;
  const { data } = await apiClient.get<BudgetStatus[]>(
    "/finops/budgets/status",
    { params },
  );
  return data;
}

