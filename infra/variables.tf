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