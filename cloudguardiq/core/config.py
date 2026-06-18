"""CloudGuardIQ -- Application settings via pydantic-settings."""

from __future__ import annotations

import json as _json
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="CLOUDGUARDIQ_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # API
    app_version: str = "0.1.0"
    debug: bool = False
    cors_origins: str = "http://localhost:3000"

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse cors_origins as JSON array or comma-separated string."""

        v = self.cors_origins.strip()
        if v.startswith("["):
            return _json.loads(v)
        return [o.strip() for o in v.split(",") if o.strip()]

    # Cosmos DB
    cosmos_endpoint: str = ""
    cosmos_database: str = "cloudguardiq"
    cosmos_container_findings: str = "findings"
    cosmos_container_snapshots: str = "snapshots"
    cosmos_container_remediations: str = "remediations"
    cosmos_container_system: str = "system"
    cosmos_container_billing: str = "billing"
    cosmos_container_subscriptions: str = "subscriptions"
    cosmos_container_tenant_consents: str = "tenant_consents"
    cosmos_container_onboarding_sessions: str = "onboarding_sessions"
    cosmos_container_cloud_connections: str = "cloud_connections"
    cosmos_container_credential_refs: str = "credential_refs"
    cosmos_container_audit_events: str = "audit_events"
    cosmos_container_focus_costs: str = "focus_costs"

    # Azure OpenAI
    azure_openai_endpoint: str = ""
    azure_openai_deployment: str = "gpt-5.1"
    # When True, every scheduled/interactive scan eagerly generates an AI
    # remediation card for each finding via the Service Bus worker -- one
    # GPT call per finding per scan, which is expensive. Default False:
    # cards are generated lazily, only when a user clicks 'Get AI
    # remediation' (POST /findings/{id}/generate-remediation), then cached.
    ai_autogenerate_on_scan: bool = False

    # Azure AD
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    # Cross-tenant credentials (Phase 3.2). Either supply a certificate
    # (preferred) via ``azure_certificate_path`` *or* fall back to the
    # client secret already provisioned by Phase 2 Terraform.
    azure_certificate_path: str = ""
    azure_client_secret: str = ""

    # Frontend redirect URI used by the admin-consent flow. The customer
    # admin is bounced back here after granting consent so we can record
    # the tenant and complete the cross-tenant onboarding handshake.
    consent_redirect_uri: str = "http://localhost:3000/settings?consent=callback"

    # Public HTTPS URL hosting the CloudGuardIQ Reader ARM template. Used
    # to build the Azure Portal "Deploy to Azure" link returned by
    # GET /subscriptions/onboarding-template. Empty string disables the
    # one-click flow (the manual `az role assignment` command still works).
    onboarding_template_uri: str = ""

    # Public, externally-resolvable base URL for the CloudGuardIQ API. When
    # set, /subscriptions/onboarding-template returns a parameters_uri that
    # the Azure Portal Deploy-to-Azure blade can fetch to pre-populate the
    # cloudGuardIQPrincipalId ARM parameter. Leave empty to disable
    # parameter prefill (the user will type the principal id manually).
    public_api_base_url: str = ""

    # Authentication
    auth_disabled: bool = False

    # Stripe billing
    stripe_api_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_free: str = ""
    stripe_price_pro: str = ""
    stripe_price_enterprise: str = ""
    stripe_success_url: str = "http://localhost:3000/settings?billing=success"
    stripe_cancel_url: str = "http://localhost:3000/settings?billing=cancel"

    # Billing mode. When Stripe is disabled (default for now), the billing
    # service is bypassed: tenants default to ``billing_default_tier`` and can
    # freely switch to any plan from Settings without a Stripe checkout.
    billing_stripe_enabled: bool = False
    billing_default_tier: str = "ENTERPRISE"

    # Tier limits (free tier)
    free_max_subscriptions: int = 1
    pro_max_subscriptions: int = 10
    enterprise_max_subscriptions: int = -1  # -1 means unlimited
    free_max_resources_per_scan: int = 100

    # Soft-delete retention for unlinked subscriptions (Phase 2.7).
    # Findings / snapshots / remediations belonging to a Removed
    # subscription are kept for this many days so a user who re-links
    # the same GUID gets their history back; expired records are then
    # hard-purged by a daily timer trigger.
    subscription_retention_days: int = 30

    # Object id of the CloudGuardIQ managed identity used by the
    # Container App / Function App when calling Azure on behalf of a
    # tenant. Surfaced by GET /onboarding/info so the Settings page can
    # render a copy-pasteable ``az role assignment create`` command.
    azure_principal_id: str = ""
    azure_principal_display_name: str = "CloudGuardIQ"

    # Compliance report storage (Phase 5.1)
    # When ``azure_storage_account_url`` is empty the API falls back to an
    # in-memory store and serves PDFs via /reports/{id}/download.
    azure_storage_account_url: str = ""
    reports_blob_container: str = "cloudguardiq-reports"


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""

    return Settings()
