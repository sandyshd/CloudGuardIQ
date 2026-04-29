export type DataTier = "TIER1_NATIVE" | "TIER2_FREE_CSPM" | "TIER3_PAID";
export type CloudProvider = "AZURE" | "AWS" | "GCP" | "TERRAFORM";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
export type FindingType = "SECURITY" | "FINOPS" | "COMPLIANCE";
export type RemediationStatus = "PENDING" | "IN_PROGRESS" | "APPLIED" | "FAILED" | "DISMISSED";

export interface ResourceSnapshot {
  id: string;
  tenant_id: string;
  provider: CloudProvider;
  subscription_id: string;
  resource_group: string;
  resource_type: string;
  resource_name: string;
  region: string;
  config: Record<string, unknown>;
  cost_monthly: number;
  tags: Record<string, string>;
  data_tier: DataTier;
  raw_hash: string;
  captured_at: string;
}

export interface FindingResult {
  finding_id: string;
  tenant_id: string;
  resource_snapshot: ResourceSnapshot | null;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  finding_type: FindingType;
  description: string;
  evidence: Record<string, unknown>;
  compliance_frameworks: string[];
  waste_monthly_usd: number;
  priority_score: number;
  detected_at: string;
}

export interface RemediationCard {
  card_id: string;
  tenant_id: string;
  finding_result: FindingResult | null;
  narrative: string;
  terraform_fix: string;
  cli_fix: string;
  confidence_qualifier: string;
  estimated_savings_usd: number;
  generated_at: string;
  model_version: string;
}

export interface ScanRequest {
  subscription_id: string;
  include_cost: boolean;
}

export interface ScanResponse {
  subscription_id: string;
  snapshots_count: number;
  findings_count: number;
  findings: FindingResult[];
}

export interface Subscription {
  subscription_id: string;
  display_name: string;
  state: string;
}

export interface DashboardMetrics {
  total_resources: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  total_waste_monthly: number;
  compliance_score: number;
}

export interface HealingEvent {
  id: string;
  finding_id: string;
  action: string;
  status: "success" | "failure" | "pending";
  timestamp: string;
  details: string;
}
