# CloudGuardIQ — Terraform Infrastructure
# =========================================
# Backend configuration for Azure Blob Storage.
# Uncomment and configure before running `terraform init`:
#
# terraform {
#   backend "azurerm" {
#     resource_group_name  = "tfstate-rg"
#     storage_account_name = "cguardiqtfstate"
#     container_name       = "tfstate"
#     key                  = "cloudguardiq.tfstate"
#   }
# }
#
# To create the backend storage:
#   az group create -n tfstate-rg -l eastus
#   az storage account create -n cguardiqtfstate -g tfstate-rg -l eastus --sku Standard_LRS
#   az storage container create -n tfstate --account-name cguardiqtfstate

terraform {
  required_version = ">= 1.8.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
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

data "azurerm_client_config" "current" {}

# ---------- Resource Group ----------
resource "azurerm_resource_group" "cloudguardiq" {
  name     = "${var.prefix}-${var.environment}-rg"
  location = var.location

  tags = local.tags
}

# ---------- Cosmos DB ----------
resource "azurerm_cosmosdb_account" "cloudguardiq" {
  name                = "${var.prefix}-${var.environment}-cosmos"
  location            = azurerm_resource_group.cloudguardiq.location
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

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

resource "azurerm_cosmosdb_sql_container" "system" {
  name                = "system"
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  account_name        = azurerm_cosmosdb_account.cloudguardiq.name
  database_name       = azurerm_cosmosdb_sql_database.cloudguardiq.name
  partition_key_paths = ["/type"]
}

# ---------- Key Vault ----------
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

# ---------- Service Bus ----------
resource "azurerm_servicebus_namespace" "cloudguardiq" {
  name                = "${var.prefix}-${var.environment}-sb"
  location            = azurerm_resource_group.cloudguardiq.location
  resource_group_name = azurerm_resource_group.cloudguardiq.name
  sku                 = "Standard"

  tags = local.tags
}

resource "azurerm_servicebus_queue" "findings_queue" {
  name         = "findings-queue"
  namespace_id = azurerm_servicebus_namespace.cloudguardiq.id
}

# ---------- Log Analytics & App Insights ----------
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

# ---------- Locals ----------
locals {
  tags = {
    project     = "cloudguardiq"
    environment = var.environment
    managed_by  = "terraform"
  }
}
