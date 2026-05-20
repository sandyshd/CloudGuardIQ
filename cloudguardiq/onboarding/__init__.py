"""CloudGuardIQ onboarding repositories."""

from cloudguardiq.onboarding.audit_event_repository import (
    AuditEventRecord,
    AuditEventRepository,
)
from cloudguardiq.onboarding.cloud_connection_repository import (
    CloudConnectionRecord,
    CloudConnectionRepository,
)
from cloudguardiq.onboarding.credential_ref_repository import (
    CredentialRefRecord,
    CredentialRefRepository,
)

__all__ = [
    "AuditEventRecord",
    "AuditEventRepository",
    "CloudConnectionRecord",
    "CloudConnectionRepository",
    "CredentialRefRecord",
    "CredentialRefRepository",
]
