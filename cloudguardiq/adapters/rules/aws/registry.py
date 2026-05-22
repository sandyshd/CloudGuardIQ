"""CloudGuardIQ — AWS rule registry.

Kept separate from the Azure ``RULE_REGISTRY`` so each cloud provider's
rule pack can evolve independently. The ``PolicyEngine`` only evaluates
rules whose ``resource_types`` match the snapshot, so it is safe to
combine both registries — see
:func:`cloudguardiq.adapters.rules.aws.registry.combined_registry`.
"""

from __future__ import annotations

from collections.abc import Sequence

from cloudguardiq.adapters.rules.aws.ec2 import (
    EbsEncryptionRule,
    InstancePublicIpRule,
    UnattachedEbsVolumeRule,
)
from cloudguardiq.adapters.rules.aws.finops import UnattachedEipRule
from cloudguardiq.adapters.rules.aws.iam import (
    IamUserNoMfaRule,
    RootAccessKeysRule,
)
from cloudguardiq.adapters.rules.aws.s3 import (
    S3BucketEncryptionRule,
    S3PublicAccessBlockRule,
    S3PublicAclRule,
)
from cloudguardiq.adapters.rules.aws.security_group import (
    RDPOpenToInternetRule,
    SSHOpenToInternetRule,
)

AWS_RULE_REGISTRY: list = [
    # S3 (3)
    S3PublicAclRule(),
    S3PublicAccessBlockRule(),
    S3BucketEncryptionRule(),
    # EC2 / EBS (3)
    EbsEncryptionRule(),
    InstancePublicIpRule(),
    UnattachedEbsVolumeRule(),
    # Security groups (2)
    SSHOpenToInternetRule(),
    RDPOpenToInternetRule(),
    # IAM (2)
    RootAccessKeysRule(),
    IamUserNoMfaRule(),
    # FinOps (1)
    UnattachedEipRule(),
]


def combined_registry(*registries: Sequence) -> list:
    """Return a flat list combining one or more rule registries."""
    out: list = []
    for reg in registries:
        out.extend(reg)
    return out
