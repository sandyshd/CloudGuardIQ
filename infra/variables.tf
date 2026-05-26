variable "prefix" {
  description = "Resource name prefix"
  type        = string
  default     = "cguardiq"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus2"
}

variable "openai_location" {
  description = "Azure region for OpenAI (limited availability)"
  type        = string
  default     = "eastus2"
}

variable "swa_location" {
  description = "Azure region for Static Web App (limited availability)"
  type        = string
  default     = "eastus2"
}

variable "openai_capacity" {
  description = "Azure OpenAI model deployment capacity (tokens per minute in thousands)"
  type        = number
  default     = 10
}

variable "api_container_image" {
  description = "Docker image for the FastAPI backend container"
  type        = string
  default     = "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest"
}

variable "frontend_redirect_uris" {
  description = "Additional redirect URIs for the Azure AD app (e.g. localhost for dev)"
  type        = list(string)
  default     = ["http://localhost:3000/"]
}
variable "deploy_sp_object_id" {
  description = "Object ID of the GitHub Actions service principal used for app deployment. If empty, falls back to the Terraform deployer identity."
  type        = string
  default     = ""
}

# ==========================================================================
# Stripe billing
# ==========================================================================
# Price IDs are non-sensitive Stripe identifiers (e.g. "price_1ABCxyz").
# The API key and webhook secret are sensitive and flow through Key Vault.

variable "stripe_price_free" {
  description = "Stripe price id for the FREE tier"
  type        = string
  default     = ""
}

variable "stripe_price_pro" {
  description = "Stripe price id for the PRO tier"
  type        = string
  default     = ""
}

variable "stripe_price_enterprise" {
  description = "Stripe price id for the ENTERPRISE tier"
  type        = string
  default     = ""
}

variable "stripe_api_key" {
  description = "Stripe secret API key (sk_live_... or sk_test_...). Pass via TF_VAR_stripe_api_key."
  type        = string
  default     = ""
  sensitive   = true
}

variable "stripe_webhook_secret" {
  description = "Stripe webhook signing secret (whsec_...). Pass via TF_VAR_stripe_webhook_secret."
  type        = string
  default     = ""
  sensitive   = true
}

variable "consent_redirect_uris" {
  description = "Additional Reply URLs for the Azure AD admin-consent callback (e.g. localhost for dev)."
  type        = list(string)
  default     = ["http://localhost:3000/settings?consent=callback"]
}

variable "onboarding_template_uri" {
  description = "Optional override for the ARM template URL used by the Azure Portal Deploy-to-Azure one-click onboarding link. When empty, the API serves its bundled copy of cloudguardiq-reader.json anonymously at {public_api_base_url}/subscriptions/onboarding-template.json -- so the GitHub repo can stay private. Set this only if you want to host the template on a CDN/Storage Account instead."
  type        = string
  default     = ""
}
