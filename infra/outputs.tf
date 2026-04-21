# ---------- Resource Group ----------
output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.cloudguardiq.name
}

# ---------- Azure AD ----------
output "azure_ad_client_id" {
  description = "Azure AD application (client) ID — use for VITE_AZURE_CLIENT_ID and backend config"
  value       = azuread_application.cloudguardiq.client_id
}

output "azure_ad_tenant_id" {
  description = "Azure AD tenant ID — use for VITE_AZURE_TENANT_ID"
  value       = data.azurerm_client_config.current.tenant_id
}

output "azure_ad_client_secret" {
  description = "Azure AD application client secret"
  value       = azuread_application_password.cloudguardiq.value
  sensitive   = true
}

# ---------- Cosmos DB ----------
output "cosmosdb_endpoint" {
  description = "Cosmos DB account endpoint"
  value       = azurerm_cosmosdb_account.cloudguardiq.endpoint
}

# ---------- Azure OpenAI ----------
output "openai_endpoint" {
  description = "Azure OpenAI endpoint"
  value       = azurerm_cognitive_account.openai.endpoint
}

# ---------- Key Vault ----------
output "key_vault_uri" {
  description = "Key Vault URI"
  value       = azurerm_key_vault.cloudguardiq.vault_uri
}

# ---------- Service Bus ----------
output "servicebus_connection_string" {
  description = "Service Bus namespace connection string"
  value       = azurerm_servicebus_namespace.cloudguardiq.default_primary_connection_string
  sensitive   = true
}

# ---------- App Insights ----------
output "appinsights_connection_string" {
  description = "Application Insights connection string"
  value       = azurerm_application_insights.cloudguardiq.connection_string
  sensitive   = true
}

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID"
  value       = azurerm_log_analytics_workspace.cloudguardiq.id
}

# ---------- Container App (Backend API) ----------
output "api_url" {
  description = "FastAPI backend URL"
  value       = "https://${azurerm_container_app.api.ingress[0].fqdn}"
}

# ---------- Functions ----------
output "function_app_name" {
  description = "Azure Function App name"
  value       = azurerm_linux_function_app.cloudguardiq.name
}

output "function_app_default_hostname" {
  description = "Azure Function App default hostname"
  value       = azurerm_linux_function_app.cloudguardiq.default_hostname
}

# ---------- Static Web App (Frontend) ----------
output "frontend_url" {
  description = "Static Web App URL for the React frontend"
  value       = "https://${azurerm_static_web_app.frontend.default_host_name}"
}

output "frontend_api_key" {
  description = "Static Web App deployment token"
  value       = azurerm_static_web_app.frontend.api_key
  sensitive   = true
}

# ---------- Convenience: .env file generator ----------
output "backend_env_file" {
  description = "Backend .env file contents (run: terraform output -raw backend_env_file > ../.env)"
  sensitive   = true
  value       = <<-EOT
    CLOUDGUARDIQ_COSMOS_ENDPOINT=${azurerm_cosmosdb_account.cloudguardiq.endpoint}
    CLOUDGUARDIQ_AZURE_OPENAI_ENDPOINT=${azurerm_cognitive_account.openai.endpoint}
    CLOUDGUARDIQ_AZURE_OPENAI_DEPLOYMENT=gpt-5.1
    CLOUDGUARDIQ_AZURE_TENANT_ID=${data.azurerm_client_config.current.tenant_id}
    CLOUDGUARDIQ_AZURE_CLIENT_ID=${azuread_application.cloudguardiq.client_id}
    AZURE_SUBSCRIPTION_ID=${data.azurerm_subscription.current.subscription_id}
    SERVICE_BUS_CONNECTION_STRING=${azurerm_servicebus_namespace.cloudguardiq.default_primary_connection_string}
  EOT
}

output "frontend_env_file" {
  description = "Frontend .env.local contents (run: terraform output -raw frontend_env_file > ../frontend/.env.local)"
  value       = <<-EOT
    VITE_AZURE_CLIENT_ID=${azuread_application.cloudguardiq.client_id}
    VITE_AZURE_TENANT_ID=${data.azurerm_client_config.current.tenant_id}
    VITE_REDIRECT_URI=http://localhost:3000
    VITE_API_BASE_URL=http://localhost:8000
  EOT
}
