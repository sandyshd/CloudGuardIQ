output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.cloudguardiq.name
}

output "cosmosdb_endpoint" {
  description = "Cosmos DB account endpoint"
  value       = azurerm_cosmosdb_account.cloudguardiq.endpoint
}

output "cosmosdb_primary_key" {
  description = "Cosmos DB primary key"
  value       = azurerm_cosmosdb_account.cloudguardiq.primary_key
  sensitive   = true
}

output "key_vault_uri" {
  description = "Key Vault URI"
  value       = azurerm_key_vault.cloudguardiq.vault_uri
}

output "servicebus_connection_string" {
  description = "Service Bus namespace connection string"
  value       = azurerm_servicebus_namespace.cloudguardiq.default_primary_connection_string
  sensitive   = true
}

output "appinsights_connection_string" {
  description = "Application Insights connection string"
  value       = azurerm_application_insights.cloudguardiq.connection_string
  sensitive   = true
}

output "appinsights_instrumentation_key" {
  description = "Application Insights instrumentation key"
  value       = azurerm_application_insights.cloudguardiq.instrumentation_key
  sensitive   = true
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID"
  value       = azurerm_log_analytics_workspace.cloudguardiq.id
}
