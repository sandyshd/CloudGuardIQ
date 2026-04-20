# CloudGuardIQ — Terraform Infrastructure
# =========================================
# Backend uses Azure Blob Storage with partial configuration.
# Values are supplied via -backend-config flags in the CI pipeline.
# For local use:
#   az group create -n tfstate-rg -l eastus
#   az storage account create -n cguardiqtfstate -g tfstate-rg -l eastus --sku Standard_LRS
#   az storage container create -n tfstate --account-name cguardiqtfstate

terraform {
  backend "azurerm" {}

  required_version = ">= 1.8.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

provider "azuread" {}

data "azurerm_client_config" "current" {}
data "azurerm_subscription" "current" {}

# ---------- Resource Group ----------
resource "azurerm_resource_group" "cloudguardiq" {
  name     = "${var.prefix}-${var.environment}-rg"
  location = var.location

  tags = local.tags
}

# ==========================================================================
# Azure AD App Registration
# ==========================================================================

resource "azuread_application" "cloudguardiq" {
  display_name = "CloudGuardIQ-${var.environment}"

  sign_in_audience = "AzureADMyOrg"

  web {
    redirect_uris = var.environment == "dev" ? [] : []

    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = false
    }
  }

  single_page_application {
    redirect_uris = concat(
      ["https://${var.prefix}-${var.environment}-swa.azurestaticapps.net/"],
      var.frontend_redirect_uris
    )
  }

  required_resource_access {
    # Azure Service Management API
    resource_app_id = "797f4846-ba00-4fd7-ba43-dac1f8f63013"

    resource_access {
      id   = "41094075-9dad-400e-a0bd-54e686782033" # user_impersonation
      type = "Scope"
    }
  }

  api {
    requested_access_token_version = 2
  }
}

resource "azuread_service_principal" "cloudguardiq" {
  client_id = azuread_application.cloudguardiq.client_id
}

resource "azuread_application_password" "cloudguardiq" {
  application_id = azuread_application.cloudguardiq.id
  display_name   = "terraform-managed"
  end_date       = timeadd(timestamp(), "8760h") # 1 year
}

# Reader role on the target subscription for scanning
resource "azurerm_role_assignment" "scanner_reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.cloudguardiq.object_id
}

# ==========================================================================
# Cosmos DB
# ==========================================================================

resource "azurerm_cosmosdb_account" "cloudguardiq" {
  name                          = "${var.prefix}-${var.environment}-cosmos"
  location                      = azurerm_resource_group.cloudguardiq.location
  resource_group_name           = azurerm_resource_group.cloudguardiq.name
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  local_authentication_disabled = true

  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.cloudguardiq.location
    failover_priority = 0
  }

  tags = local.tags
}

resource "azurerm_cosmosdb_sql_database" "cloudguardiq" {
  name                = "cloudguardiq"
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  account_name        = azurerm_cosmosdb_account.cloudguardiq.name
}

resource "azurerm_cosmosdb_sql_container" "findings" {
  name                = "findings"
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  account_name        = azurerm_cosmosdb_account.cloudguardiq.name
  database_name       = azurerm_cosmosdb_sql_database.cloudguardiq.name
  partition_key_paths = ["/subscription_id"]
}

resource "azurerm_cosmosdb_sql_container" "snapshots" {
  name                = "snapshots"
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  account_name        = azurerm_cosmosdb_account.cloudguardiq.name
  database_name       = azurerm_cosmosdb_sql_database.cloudguardiq.name
  partition_key_paths = ["/provider"]
}

resource "azurerm_cosmosdb_sql_container" "remediations" {
  name                = "remediations"
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  account_name        = azurerm_cosmosdb_account.cloudguardiq.name
  database_name       = azurerm_cosmosdb_sql_database.cloudguardiq.name
  partition_key_paths = ["/finding_id"]
}

resource "azurerm_cosmosdb_sql_container" "system" {
  name                = "system"
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  account_name        = azurerm_cosmosdb_account.cloudguardiq.name
  database_name       = azurerm_cosmosdb_sql_database.cloudguardiq.name
  partition_key_paths = ["/type"]
}

# ==========================================================================
# Azure OpenAI
# ==========================================================================

resource "azurerm_cognitive_account" "openai" {
  name                  = "${var.prefix}-${var.environment}-openai"
  location              = var.openai_location
  resource_group_name   = azurerm_resource_group.cloudguardiq.name
  kind                  = "OpenAI"
  sku_name              = "S0"
  custom_subdomain_name = "${var.prefix}-${var.environment}-openai"
  local_auth_enabled    = false

  tags = local.tags
}

resource "azurerm_cognitive_deployment" "gpt4o" {
  name                 = "gpt-4o"
  cognitive_account_id = azurerm_cognitive_account.openai.id

  model {
    format  = "OpenAI"
    name    = "gpt-4o"
    version = "2024-08-06"
  }

  scale {
    type     = "Standard"
    capacity = var.openai_capacity
  }
}

# ==========================================================================
# Key Vault (retained for non-key secrets like Service Bus connection string)
# ==========================================================================

resource "azurerm_key_vault" "cloudguardiq" {
  name                       = "${var.prefix}-${var.environment}-kv"
  location                   = azurerm_resource_group.cloudguardiq.location
  resource_group_name        = azurerm_resource_group.cloudguardiq.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = true

  tags = local.tags
}

# Access policy: Terraform deployer (current principal)
resource "azurerm_key_vault_access_policy" "deployer" {
  key_vault_id = azurerm_key_vault.cloudguardiq.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  secret_permissions = ["Get", "List", "Set", "Delete", "Purge"]
}

# Access policy: Container App managed identity
resource "azurerm_key_vault_access_policy" "container_app" {
  key_vault_id = azurerm_key_vault.cloudguardiq.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_container_app.api.identity[0].principal_id

  secret_permissions = ["Get", "List"]
}

# Access policy: Function App managed identity
resource "azurerm_key_vault_access_policy" "function_app" {
  key_vault_id = azurerm_key_vault.cloudguardiq.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_linux_function_app.cloudguardiq.identity[0].principal_id

  secret_permissions = ["Get", "List"]
}

# Secrets (only non-key secrets remain)
resource "azurerm_key_vault_secret" "servicebus_connection" {
  name         = "servicebus-connection-string"
  value        = azurerm_servicebus_namespace.cloudguardiq.default_primary_connection_string
  key_vault_id = azurerm_key_vault.cloudguardiq.id

  depends_on = [azurerm_key_vault_access_policy.deployer]
}

resource "azurerm_key_vault_secret" "app_client_secret" {
  name         = "app-client-secret"
  value        = azuread_application_password.cloudguardiq.value
  key_vault_id = azurerm_key_vault.cloudguardiq.id

  depends_on = [azurerm_key_vault_access_policy.deployer]
}

# ==========================================================================
# RBAC Role Assignments — Cosmos DB
# ==========================================================================

# Cosmos DB Built-in Data Contributor for Container App managed identity
resource "azurerm_cosmosdb_sql_role_assignment" "container_app_cosmos" {
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  account_name        = azurerm_cosmosdb_account.cloudguardiq.name
  # Built-in "Cosmos DB Built-in Data Contributor" role definition ID
  role_definition_id = "${azurerm_cosmosdb_account.cloudguardiq.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id       = azurerm_container_app.api.identity[0].principal_id
  scope              = azurerm_cosmosdb_account.cloudguardiq.id
}

# Cosmos DB Built-in Data Contributor for Function App managed identity
resource "azurerm_cosmosdb_sql_role_assignment" "function_app_cosmos" {
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  account_name        = azurerm_cosmosdb_account.cloudguardiq.name
  role_definition_id  = "${azurerm_cosmosdb_account.cloudguardiq.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = azurerm_linux_function_app.cloudguardiq.identity[0].principal_id
  scope               = azurerm_cosmosdb_account.cloudguardiq.id
}

# ==========================================================================
# RBAC Role Assignments — Azure OpenAI
# ==========================================================================

# Cognitive Services OpenAI User for Container App managed identity
resource "azurerm_role_assignment" "container_app_openai" {
  scope                = azurerm_cognitive_account.openai.id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = azurerm_container_app.api.identity[0].principal_id
}

# Cognitive Services OpenAI User for Function App managed identity
resource "azurerm_role_assignment" "function_app_openai" {
  scope                = azurerm_cognitive_account.openai.id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = azurerm_linux_function_app.cloudguardiq.identity[0].principal_id
}

# ==========================================================================
# Service Bus
# ==========================================================================

resource "azurerm_servicebus_namespace" "cloudguardiq" {
  name                = "${var.prefix}-${var.environment}-sbus"
  location            = azurerm_resource_group.cloudguardiq.location
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  sku                 = "Standard"

  tags = local.tags
}

resource "azurerm_servicebus_queue" "findings_queue" {
  name         = "findings-queue"
  namespace_id = azurerm_servicebus_namespace.cloudguardiq.id
}

# ==========================================================================
# Log Analytics & App Insights
# ==========================================================================

resource "azurerm_log_analytics_workspace" "cloudguardiq" {
  name                = "${var.prefix}-${var.environment}-law"
  location            = azurerm_resource_group.cloudguardiq.location
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = local.tags
}

resource "azurerm_application_insights" "cloudguardiq" {
  name                = "${var.prefix}-${var.environment}-ai"
  location            = azurerm_resource_group.cloudguardiq.location
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  workspace_id        = azurerm_log_analytics_workspace.cloudguardiq.id
  application_type    = "web"

  tags = local.tags
}

# ==========================================================================
# Container Apps — FastAPI Backend
# ==========================================================================

resource "azurerm_container_app_environment" "cloudguardiq" {
  name                       = "${var.prefix}-${var.environment}-cae"
  location                   = azurerm_resource_group.cloudguardiq.location
  resource_group_name        = azurerm_resource_group.cloudguardiq.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.cloudguardiq.id

  tags = local.tags
}

resource "azurerm_container_app" "api" {
  name                         = "${var.prefix}-${var.environment}-api"
  container_app_environment_id = azurerm_container_app_environment.cloudguardiq.id
  resource_group_name          = azurerm_resource_group.cloudguardiq.name
  revision_mode                = "Single"

  identity {
    type = "SystemAssigned"
  }

  template {
    min_replicas = var.environment == "prod" ? 1 : 0
    max_replicas = var.environment == "prod" ? 3 : 1

    container {
      name   = "api"
      image  = var.api_container_image
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "CLOUDGUARDIQ_COSMOS_ENDPOINT"
        value = azurerm_cosmosdb_account.cloudguardiq.endpoint
      }
      env {
        name  = "CLOUDGUARDIQ_AZURE_OPENAI_ENDPOINT"
        value = azurerm_cognitive_account.openai.endpoint
      }
      env {
        name  = "CLOUDGUARDIQ_AZURE_OPENAI_DEPLOYMENT"
        value = "gpt-4o"
      }
      env {
        name  = "CLOUDGUARDIQ_AZURE_TENANT_ID"
        value = data.azurerm_client_config.current.tenant_id
      }
      env {
        name  = "CLOUDGUARDIQ_AZURE_CLIENT_ID"
        value = azuread_application.cloudguardiq.client_id
      }
      env {
        name  = "CLOUDGUARDIQ_CORS_ORIGINS"
        value = "[\"https://${var.prefix}-${var.environment}-swa.azurestaticapps.net\"]"
      }
      env {
        name  = "APPLICATIONINSIGHTS_CONNECTION_STRING"
        value = azurerm_application_insights.cloudguardiq.connection_string
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "http"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  tags = local.tags
}

# Reader role for Container App managed identity (scanning)
resource "azurerm_role_assignment" "container_app_reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Reader"
  principal_id         = azurerm_container_app.api.identity[0].principal_id
}

# ==========================================================================
# Azure Functions — Timer-Triggered Scans + AI Worker
# ==========================================================================

resource "azurerm_storage_account" "functions" {
  name                     = "${var.prefix}${var.environment}func"
  location                 = azurerm_resource_group.cloudguardiq.location
  resource_group_name      = azurerm_resource_group.cloudguardiq.name
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = local.tags
}

resource "azurerm_service_plan" "functions" {
  name                = "${var.prefix}-${var.environment}-asp"
  location            = azurerm_resource_group.cloudguardiq.location
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  os_type             = "Linux"
  sku_name            = "Y1"

  tags = local.tags
}

# Storage Blob Data Owner for Function App to use managed identity for storage
resource "azurerm_role_assignment" "function_app_storage" {
  scope                = azurerm_storage_account.functions.id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = azurerm_linux_function_app.cloudguardiq.identity[0].principal_id
}

resource "azurerm_role_assignment" "function_app_storage_queue" {
  scope                = azurerm_storage_account.functions.id
  role_definition_name = "Storage Queue Data Contributor"
  principal_id         = azurerm_linux_function_app.cloudguardiq.identity[0].principal_id
}

resource "azurerm_role_assignment" "function_app_storage_table" {
  scope                = azurerm_storage_account.functions.id
  role_definition_name = "Storage Table Data Contributor"
  principal_id         = azurerm_linux_function_app.cloudguardiq.identity[0].principal_id
}

resource "azurerm_linux_function_app" "cloudguardiq" {
  name                = "${var.prefix}-${var.environment}-func"
  location            = azurerm_resource_group.cloudguardiq.location
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  service_plan_id     = azurerm_service_plan.functions.id

  storage_account_name          = azurerm_storage_account.functions.name
  storage_uses_managed_identity = true

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      python_version = "3.12"
    }

    application_insights_connection_string = azurerm_application_insights.cloudguardiq.connection_string
  }

  app_settings = {
    # Cosmos DB (RBAC via managed identity)
    CLOUDGUARDIQ_COSMOS_ENDPOINT = azurerm_cosmosdb_account.cloudguardiq.endpoint

    # Azure OpenAI (RBAC via managed identity)
    AZURE_OPENAI_ENDPOINT   = azurerm_cognitive_account.openai.endpoint
    AZURE_OPENAI_DEPLOYMENT = "gpt-4o"

    # Subscription to scan
    AZURE_SUBSCRIPTION_ID = data.azurerm_subscription.current.subscription_id

    # Service Bus
    SERVICE_BUS_CONNECTION_STRING = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.servicebus_connection.id})"

    # Azure AD
    CLOUDGUARDIQ_AZURE_TENANT_ID = data.azurerm_client_config.current.tenant_id
    CLOUDGUARDIQ_AZURE_CLIENT_ID = azuread_application.cloudguardiq.client_id
  }

  tags = local.tags
}

# Reader role for Function App managed identity (scanning)
resource "azurerm_role_assignment" "function_app_reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Reader"
  principal_id         = azurerm_linux_function_app.cloudguardiq.identity[0].principal_id
}

# ==========================================================================
# Static Web App — React Frontend
# ==========================================================================

resource "azurerm_static_web_app" "frontend" {
  name                = "${var.prefix}-${var.environment}-swa"
  location            = var.swa_location
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  sku_tier            = "Free"
  sku_size            = "Free"

  tags = local.tags
}

# ==========================================================================
# Locals
# ==========================================================================

locals {
  tags = {
    project     = "cloudguardiq"
    environment = var.environment
    managed_by  = "terraform"
  }
}
