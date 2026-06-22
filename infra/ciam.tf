# ==========================================================================
# Microsoft Entra External ID (CIAM) — customer sign-up app registration
# ==========================================================================
# Phase 4: lets AWS/GCP-only customers sign up with email or Google without an
# Azure tenant. The CIAM directory is a SEPARATE Entra External ID tenant
# (stood up via the External ID onboarding, out of band) — distinct from the
# multi-tenant workforce scanning app (azuread_application.cloudguardiq).
#
# This app registration lives IN that CIAM tenant, reached through an aliased
# azuread provider. All CIAM resources are gated on var.ciam_enabled so the
# core deployment stays green for Azure-only environments that have not yet
# provisioned a CIAM tenant.

provider "azuread" {
  alias     = "ciam"
  tenant_id = var.ciam_tenant_id
}

resource "azuread_application" "ciam" {
  count = var.ciam_enabled ? 1 : 0

  provider     = azuread.ciam
  display_name = "CloudGuardIQ-CIAM-${var.environment}"

  # External ID customers all live in the single CIAM tenant.
  sign_in_audience = "AzureADMyOrg"

  single_page_application {
    # The React SPA redirects here after a CIAM (email/Google) login. MSAL
    # validates the issued token audience == this app's client id, which the
    # FastAPI backend also enforces (CLOUDGUARDIQ_CIAM_CLIENT_ID).
    redirect_uris = concat(
      ["https://${azurerm_static_web_app.frontend.default_host_name}/"],
      var.ciam_frontend_redirect_uris,
    )
  }

  required_resource_access {
    # Microsoft Graph -- delegated User.Read so the SPA can read the signed-in
    # customer's basic profile. The backend mints the cloud-neutral org_id; no
    # application Graph permissions are required for CIAM sign-up.
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph

    resource_access {
      id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read (delegated)
      type = "Scope"
    }
  }

  api {
    requested_access_token_version = 2
  }
}

resource "azuread_service_principal" "ciam" {
  count = var.ciam_enabled ? 1 : 0

  provider  = azuread.ciam
  client_id = azuread_application.ciam[0].client_id
}
