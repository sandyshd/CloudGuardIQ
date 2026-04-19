---
applyTo: "infra/**/*.tf"
---
- Use azurerm provider with features block
- All resource names use var.prefix + var.environment pattern
- Enable encryption on all storage resources
- Tag all resources with: environment, project, managed_by
- Never hardcode subscription IDs or tenant IDs