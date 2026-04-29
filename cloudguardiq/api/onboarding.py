"""CloudGuardIQ -- Onboarding helpers (Phase 2.8).

Surfaces the data a tenant needs to grant CloudGuardIQ Reader access on
their Azure subscription before linking it. The principal id is
discovered at runtime by ``identity_resolver`` -- see that module for
why this is not a Terraform input.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from cloudguardiq.core.config import get_settings
from cloudguardiq.core.identity_resolver import resolve_principal_id


class OnboardingInfo(BaseModel):
    """Public info used by the Settings UI to drive the link flow."""

    azure_principal_id: str
    azure_principal_display_name: str
    role: str = "Reader"
    az_command_template: str

    @classmethod
    def build(cls) -> OnboardingInfo:
        settings = get_settings()
        principal = resolve_principal_id(settings.azure_principal_id)
        cmd = (
            "az role assignment create "
            f"--assignee {principal} "
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
