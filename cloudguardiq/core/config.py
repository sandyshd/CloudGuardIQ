"""CloudGuardIQ -- Application settings via pydantic-settings."""

from __future__ import annotations

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
    cors_origins: list[str] = ["http://localhost:3000"]

    # Cosmos DB
    cosmos_endpoint: str = ""
    cosmos_database: str = "cloudguardiq"
    cosmos_container_findings: str = "findings"
    cosmos_container_snapshots: str = "snapshots"
    cosmos_container_remediations: str = "remediations"
    cosmos_container_system: str = "system"
    cosmos_container_billing: str = "billing"

    # Azure OpenAI
    azure_openai_endpoint: str = ""
    azure_openai_deployment: str = "gpt-5.1"

    # Azure AD
    azure_tenant_id: str = ""
    azure_client_id: str = ""

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

    # Tier limits (free tier)
    free_max_subscriptions: int = 1
    free_max_resources_per_scan: int = 50


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
