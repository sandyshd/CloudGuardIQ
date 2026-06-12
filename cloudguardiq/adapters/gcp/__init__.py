"""CloudGuardIQ - GCP adapter package."""

from cloudguardiq.adapters.gcp.adapter import GCPAdapter
from cloudguardiq.adapters.gcp.gcp_policy_compliance_adapter import (
    GCPPolicyComplianceAdapter,
)

__all__ = ["GCPAdapter", "GCPPolicyComplianceAdapter"]
