"""CloudGuardIQ -- Onboarding helpers (Phase 2.8).

Surfaces the data a tenant needs to grant CloudGuardIQ Reader access on
their Azure subscription before linking it. The principal ID belongs to
the CloudGuardIQ managed identity (set at deploy time via the
``CLOUDGUARDIQ_AZURE_PRINCIPAL_ID`` env var).
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from cloudguardiq.core.config import get_settings


class OnboardingInfo(BaseModel):
    """Public info used by the Settings UI to drive the link flow."""

    azure_principal_id: str
    azure_principal_display_name: str
    role: str = "Reader"
    az_command_template: str

    @classmethod
    def build(cls) -> OnboardingInfo:
        settings = get_settings()
        principal = settings.azure_principal_id or "<principal-id-not-configured>"
        cmd = (
            "az role assignment create "
            f'--assignee {principal} '
            "--role Reader "
            "--scope /subscriptions/<your-subscription-id>"
        )
        return cls(
            azure_principal_id=principal,
            azure_principal_display_name=settings.azure_principal_display_name,
            az_command_template=cmd,
        )


router = APIRouter(prefix="/onboarding", tags=["onboarding"])


@router.get("/info", response_model=OnboardingInfo)
async def get_onboarding_info() -> OnboardingInfo:
    """Return the public RBAC info needed to link a new Azure subscription."""
    return OnboardingInfo.build()
