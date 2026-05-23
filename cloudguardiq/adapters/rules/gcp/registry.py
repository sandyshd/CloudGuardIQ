"""CloudGuardIQ -- GCP rule registry.

Provides ``GCP_RULE_REGISTRY``, a flat list of instantiated PolicyRule
objects. The list is consumed by ``PolicyEngine`` discovery and can be
combined with other registries via ``combined_registry``.
"""

from __future__ import annotations

from cloudguardiq.adapters.rules.gcp.compute import (
    DiskCmekEncryptionRule,
    InstancePublicIpRule,
    UnattachedDiskRule,
)
from cloudguardiq.adapters.rules.gcp.iam import ServiceAccountUserManagedKeyRule
from cloudguardiq.adapters.rules.gcp.network import (
    FirewallRdpOpenRule,
    FirewallSshOpenRule,
)
from cloudguardiq.adapters.rules.gcp.storage import (
    BucketPublicAccessRule,
    BucketUniformAccessRule,
)

GCP_RULE_REGISTRY: list = [
    InstancePublicIpRule(),
    DiskCmekEncryptionRule(),
    UnattachedDiskRule(),
    BucketPublicAccessRule(),
    BucketUniformAccessRule(),
    ServiceAccountUserManagedKeyRule(),
    FirewallSshOpenRule(),
    FirewallRdpOpenRule(),
]

__all__ = ["GCP_RULE_REGISTRY"]
