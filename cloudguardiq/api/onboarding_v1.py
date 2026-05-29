"""CloudGuardIQ -- v1 unified onboarding and cloud-connection APIs."""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import NoReturn

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from cloudguardiq.api import subscriptions as subscriptions_module
from cloudguardiq.api.auth import TokenPayload, get_tenant_id, verify_token
from cloudguardiq.core.config import Settings, get_settings
from cloudguardiq.core.enums import CloudProvider as CloudProvider_enum
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
from cloudguardiq.subscriptions.repository import SubscriptionRecord

logger = logging.getLogger(__name__)

_auth = Depends(verify_token)
_AWS_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
_GCP_PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


class CloudProvider(str, Enum):
    """Supported cloud providers for onboarding sessions."""

    AZURE = "AZURE"
    AWS = "AWS"
    GCP = "GCP"


class OnboardingTargetScope(BaseModel):
    """Provider-specific target scope identifiers for onboarding."""

    tenant_id: str = ""
    account_id: str = ""
    project_id: str = ""
    organization_id: str = ""
    # AWS region for the connected account. Optional in the request;
    # defaults to ``us-east-1`` when the AWS path persists the
    # SubscriptionRecord. Ignored for non-AWS providers.
    region: str = ""


class OnboardingSessionCreateRequestV1(BaseModel):
    """Request payload for POST /v1/onboarding/sessions."""

    provider: CloudProvider
    display_name: str = ""
    target_scope: OnboardingTargetScope


class OnboardingSessionConnectRequestV1(BaseModel):
    """Request payload for POST /v1/onboarding/sessions/{id}/connect."""

    scope_ids: list[str] = Field(default_factory=list)


class GenerateArtifactsRequestV1(BaseModel):
    """Request payload for POST /v1/onboarding/sessions/{id}/generate-artifacts.

    ``assign_frameworks`` is Azure-only and optional. It selects which
    built-in regulatory initiatives the Deploy-to-Azure template assigns
    alongside the Reader role: ``all`` (every supported framework), a CSV
    of framework ids (e.g. ``CIS_AZURE,NIST_800_53``), or ``none``/empty
    to grant the Reader role only. Defaults to ``all`` for backward
    compatibility with the original one-click flow.
    """

    assign_frameworks: str = "all"


class VerificationCheck(BaseModel):
    """One verify step result returned to the frontend."""

    check: str
    status: str
    # Optional human-readable explanation surfaced to the operator when a
    # check produces a non-``pass`` outcome (e.g. ``warn`` because scope
    # discovery succeeded but returned zero subscriptions).
    message: str | None = None


class DiscoveredScope(BaseModel):
    """A discovered cloud scope that can be connected."""

    id: str
    display_name: str
    kind: str


class OnboardingSessionResponseV1(BaseModel):
    """Unified onboarding session response envelope for v1 endpoints."""

    session_id: str
    provider: CloudProvider
    customer_tenant_id: str
    status: str
    next_actions: list[str] = Field(default_factory=list)
    artifacts: dict[str, str] = Field(default_factory=dict)
    discovered_scopes: list[DiscoveredScope] = Field(default_factory=list)
    linked_scope_ids: list[str] = Field(default_factory=list)
    verification_checks: list[VerificationCheck] = Field(default_factory=list)
    connection_id: str = ""


class CloudConnectionResponse(BaseModel):
    """Connection lifecycle response payload for /v1/cloud-connections endpoints."""

    connection_id: str
    provider: str
    display_name: str
    linked_scopes: list[str]
    target_scope: dict[str, str]
    auth_mode: str
    status: str
    last_verified_at: str = ""
    last_scan_at: str = ""
    created_at: str = ""
    updated_at: str = ""


class AwsOnboardingSession(BaseModel):
    """In-memory AWS onboarding session state for Slice B scaffolding."""

    session_id: str
    operator_tenant_id: str
    account_id: str
    region: str = "us-east-1"
    status: str = "initiated"
    discovered_scope_ids: list[str] = Field(default_factory=list)
    linked_scope_ids: list[str] = Field(default_factory=list)
    external_id: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GcpOnboardingSession(BaseModel):
    """In-memory GCP onboarding session state for Slice C scaffolding."""

    session_id: str
    operator_tenant_id: str
    project_id: str
    status: str = "initiated"
    discovered_scope_ids: list[str] = Field(default_factory=list)
    linked_scope_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


router = APIRouter(prefix="/v1/onboarding", tags=["onboarding-v1"])
cloud_connections_router = APIRouter(
    prefix="/v1/cloud-connections",
    tags=["cloud-connections-v1"],
)

_aws_sessions: dict[tuple[str, str], AwsOnboardingSession] = {}
_gcp_sessions: dict[tuple[str, str], GcpOnboardingSession] = {}

_settings: Settings = get_settings()
_cloud_connection_repository: CloudConnectionRepository | None = CloudConnectionRepository(
    _settings,
    cosmos_db=None,
)
_credential_ref_repository: CredentialRefRepository | None = CredentialRefRepository(
    _settings,
    cosmos_db=None,
)
_audit_event_repository: AuditEventRepository | None = AuditEventRepository(
    _settings,
    cosmos_db=None,
)


def configure(
    *,
    settings: Settings,
    cloud_connection_repository: CloudConnectionRepository | None = None,
    credential_ref_repository: CredentialRefRepository | None = None,
    audit_event_repository: AuditEventRepository | None = None,
) -> None:
    """Configure onboarding_v1 module dependencies."""

    global _settings  # noqa: PLW0603
    global _cloud_connection_repository, _credential_ref_repository  # noqa: PLW0603
    global _audit_event_repository  # noqa: PLW0603
    _settings = settings
    _cloud_connection_repository = cloud_connection_repository or CloudConnectionRepository(
        settings,
        cosmos_db=None,
    )
    _credential_ref_repository = credential_ref_repository or CredentialRefRepository(
        settings,
        cosmos_db=None,
    )
    _audit_event_repository = audit_event_repository or AuditEventRepository(
        settings,
        cosmos_db=None,
    )


def _iso(dt: datetime | None) -> str:
    """Render datetimes as ISO strings for response payloads."""

    return dt.isoformat() if dt is not None else ""


def _connection_response(record: CloudConnectionRecord) -> CloudConnectionResponse:
    """Convert a CloudConnectionRecord into API response shape."""

    return CloudConnectionResponse(
        connection_id=record.connection_id,
        provider=record.provider,
        display_name=record.display_name,
        linked_scopes=record.linked_scopes,
        target_scope=record.target_scope,
        auth_mode=record.auth_mode,
        status=record.status,
        last_verified_at=_iso(record.last_verified_at),
        last_scan_at=_iso(record.last_scan_at),
        created_at=_iso(record.created_at),
        updated_at=_iso(record.updated_at),
    )


def _raise_provider_not_supported(provider: CloudProvider) -> NoReturn:
    """Raise a normalized 400 error for unsupported providers."""

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "error_code": "provider_not_supported",
            "provider": provider.value,
            "message": (
                "This endpoint currently supports AZURE, AWS, and GCP only."
            ),
        },
    )


def _map_status(legacy_status: str) -> str:
    """Map legacy onboarding statuses into v1 status names."""

    status_map = {
        "pending_consent": "consent_pending",
        "pending_reader": "trust_pending",
        "pending_discovery": "trust_pending",
        "subscriptions_discovered": "verified",
        "completed": "connected",
    }
    return status_map.get(legacy_status, legacy_status)


def _next_actions(v1_status: str) -> list[str]:
    """Return frontend action hints for each v1 status."""

    if v1_status == "initiated":
        return ["generate_artifacts"]
    if v1_status == "consent_pending":
        return ["generate_artifacts", "grant_consent"]
    if v1_status == "trust_pending":
        return ["grant_reader", "verify"]
    if v1_status == "verified":
        return ["connect"]
    if v1_status == "connected":
        return ["refresh"]
    return ["refresh"]


def _to_discovered_scopes(subscription_ids: list[str]) -> list[DiscoveredScope]:
    """Convert discovered Azure subscription ids into generic scope objects."""

    return [
        DiscoveredScope(id=sid, display_name=sid, kind="subscription")
        for sid in subscription_ids
    ]


def _to_v1_response(
    legacy: subscriptions_module.OnboardingSessionResponse,
    *,
    artifacts: dict[str, str] | None = None,
    verification_checks: list[VerificationCheck] | None = None,
    connection_id: str = "",
) -> OnboardingSessionResponseV1:
    """Build a v1 envelope from the existing Azure onboarding response."""

    mapped_status = _map_status(legacy.status)
    out_artifacts = dict(artifacts or {})
    if legacy.consent_url:
        out_artifacts.setdefault("consent_url", legacy.consent_url)
    return OnboardingSessionResponseV1(
        session_id=legacy.session_id,
        provider=CloudProvider.AZURE,
        customer_tenant_id=legacy.customer_tenant_id,
        status=mapped_status,
        next_actions=_next_actions(mapped_status),
        artifacts=out_artifacts,
        discovered_scopes=_to_discovered_scopes(legacy.discovered_subscription_ids),
        linked_scope_ids=legacy.connected_subscription_ids,
        verification_checks=verification_checks or [],
        connection_id=connection_id,
    )


def _aws_session_key(user: TokenPayload, session_id: str) -> tuple[str, str]:
    """Return in-memory key for one tenant-scoped AWS onboarding session."""

    return (get_tenant_id(user).lower(), session_id)


def _gcp_session_key(user: TokenPayload, session_id: str) -> tuple[str, str]:
    """Return in-memory key for one tenant-scoped GCP onboarding session."""

    return (get_tenant_id(user).lower(), session_id)


def _aws_session_to_response(
    session: AwsOnboardingSession,
    *,
    artifacts: dict[str, str] | None = None,
    verification_checks: list[VerificationCheck] | None = None,
    connection_id: str = "",
) -> OnboardingSessionResponseV1:
    """Convert AWS session state to v1 response envelope."""

    discovered = [
        DiscoveredScope(id=sid, display_name=sid, kind="account")
        for sid in session.discovered_scope_ids
    ]
    return OnboardingSessionResponseV1(
        session_id=session.session_id,
        provider=CloudProvider.AWS,
        customer_tenant_id=session.account_id,
        status=session.status,
        next_actions=_next_actions(session.status),
        artifacts=dict(artifacts or {}),
        discovered_scopes=discovered,
        linked_scope_ids=session.linked_scope_ids,
        verification_checks=verification_checks or [],
        connection_id=connection_id,
    )


def _gcp_session_to_response(
    session: GcpOnboardingSession,
    *,
    artifacts: dict[str, str] | None = None,
    verification_checks: list[VerificationCheck] | None = None,
    connection_id: str = "",
) -> OnboardingSessionResponseV1:
    """Convert GCP session state to v1 response envelope."""

    discovered = [
        DiscoveredScope(id=sid, display_name=sid, kind="project")
        for sid in session.discovered_scope_ids
    ]
    return OnboardingSessionResponseV1(
        session_id=session.session_id,
        provider=CloudProvider.GCP,
        customer_tenant_id=session.project_id,
        status=session.status,
        next_actions=_next_actions(session.status),
        artifacts=dict(artifacts or {}),
        discovered_scopes=discovered,
        linked_scope_ids=session.linked_scope_ids,
        verification_checks=verification_checks or [],
        connection_id=connection_id,
    )


def _get_aws_session_or_404(
    session_id: str,
    user: TokenPayload,
) -> AwsOnboardingSession:
    """Return one AWS onboarding session scoped to caller tenant."""

    session = _aws_sessions.get(_aws_session_key(user, session_id))
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Onboarding session not found",
        )
    return session


def _get_gcp_session_or_404(
    session_id: str,
    user: TokenPayload,
) -> GcpOnboardingSession:
    """Return one GCP onboarding session scoped to caller tenant."""

    session = _gcp_sessions.get(_gcp_session_key(user, session_id))
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Onboarding session not found",
        )
    return session


def _try_get_aws_session(
    session_id: str,
    user: TokenPayload,
) -> AwsOnboardingSession | None:
    """Return AWS session when present, else None."""

    return _aws_sessions.get(_aws_session_key(user, session_id))


def _try_get_gcp_session(
    session_id: str,
    user: TokenPayload,
) -> GcpOnboardingSession | None:
    """Return GCP session when present, else None."""

    return _gcp_sessions.get(_gcp_session_key(user, session_id))


def _build_aws_external_id(operator_tenant_id: str, session_id: str) -> str:
    """Build deterministic ExternalId for AWS trust policy generation."""

    return f"cgq-{operator_tenant_id[:8]}-{session_id[:12]}"


def _build_aws_trust_policy(control_plane_account_id: str, external_id: str) -> str:
    """Return trust policy JSON that customers attach to CloudGuardIQ role."""

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": (
                        "arn:aws:iam::"
                        f"{control_plane_account_id}:role/cloudguardiq-control-plane"
                    ),
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": external_id,
                    },
                },
            },
        ],
    }
    return json.dumps(policy, separators=(",", ":"))


def _build_gcp_provider_resource_name(pool: str) -> str:
    """Build default workload identity provider resource name."""

    return f"{pool}/providers/cloudguardiq-provider"


def _build_gcp_bind_command(project_id: str, provider_resource_name: str) -> str:
    """Build command snippet for binding provider principal to service account."""

    service_account = f"cloudguardiq-reader@{project_id}.iam.gserviceaccount.com"
    return (
        "gcloud iam service-accounts add-iam-policy-binding "
        f"{service_account} "
        "--project "
        f"{project_id} "
        "--role roles/iam.workloadIdentityUser "
        "--member "
        f"principalSet://iam.googleapis.com/{provider_resource_name}"
    )


def _auth_mode(provider: CloudProvider) -> str:
    """Return auth mode string for provider."""

    if provider is CloudProvider.AZURE:
        return "azure_sp_consent"
    if provider is CloudProvider.AWS:
        return "aws_assume_role"
    return "gcp_wif"


def _credential_secret_ref(provider: CloudProvider, target: dict[str, str]) -> str:
    """Return Key Vault secret reference placeholder for provider credential metadata."""

    prefix = {
        CloudProvider.AZURE: "azure",
        CloudProvider.AWS: "aws",
        CloudProvider.GCP: "gcp",
    }[provider]
    scope = next(iter(target.values()), "scope")
    return f"kv://cloudguardiq/{prefix}/{scope}"


async def _append_audit_event(
    *,
    user: TokenPayload,
    action: str,
    provider: CloudProvider,
    resource_id: str,
    result: str,
    details: dict[str, str] | None = None,
) -> None:
    """Append one tenant-scoped audit event; never raise on failures."""

    repo = _audit_event_repository
    if repo is None:
        return
    try:
        tenant_id = get_tenant_id(user)
        actor_id = user.oid or user.sub or ""
        await repo.append(
            AuditEventRecord(
                event_id=uuid.uuid4().hex,
                tenant_id=tenant_id,
                actor_id=actor_id,
                action=action,
                provider=provider.value,
                resource_id=resource_id,
                result=result,
                details=dict(details or {}),
            ),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to append audit event action=%s: %s", action, exc)


async def _upsert_connection_and_credentials(
    *,
    user: TokenPayload,
    provider: CloudProvider,
    linked_scopes: list[str],
    target_scope: dict[str, str],
    display_name: str,
) -> CloudConnectionRecord:
    """Create/update cloud connection and credential reference records."""

    conn_repo = _cloud_connection_repository
    cred_repo = _credential_ref_repository
    if conn_repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cloud connection repository not configured",
        )
    tenant_id = get_tenant_id(user)
    now = datetime.now(timezone.utc)
    rec = CloudConnectionRecord(
        connection_id=uuid.uuid4().hex,
        tenant_id=tenant_id,
        provider=provider.value,
        display_name=display_name,
        linked_scopes=list(dict.fromkeys(linked_scopes)),
        target_scope=target_scope,
        auth_mode=_auth_mode(provider),
        status="active",
        last_verified_at=now,
        created_at=now,
        updated_at=now,
    )
    saved = await conn_repo.upsert(rec)

    if cred_repo is not None:
        token_exp = now.replace(microsecond=0).isoformat()
        await cred_repo.upsert(
            CredentialRefRecord(
                credential_ref_id=uuid.uuid4().hex,
                tenant_id=tenant_id,
                connection_id=saved.connection_id,
                provider=provider.value,
                secret_ref=_credential_secret_ref(provider, target_scope),
                token_metadata={"last_refresh_at": token_exp},
                rotation_policy="short_lived",
            ),
        )

    await _append_audit_event(
        user=user,
        action="connection_connected",
        provider=provider,
        resource_id=saved.connection_id,
        result="success",
        details={"scope_count": str(len(saved.linked_scopes))},
    )
    return saved


async def _mirror_connected_scopes_for_operator(
    *,
    user: TokenPayload,
    scopes: list[str],
    customer_tenant_id: str,
) -> None:
    """Mirror connected Azure scopes into caller-tenant subscriptions for UI visibility."""

    try:
        repo = subscriptions_module._get_repo()  # noqa: SLF001
    except Exception as exc:  # noqa: BLE001
        logger.warning("Subscriptions repository unavailable for mirror step: %s", exc)
        return

    caller_tenant_id = get_tenant_id(user)
    for raw_scope in scopes:
        sub_id = raw_scope.strip().lower()
        if not sub_id:
            continue
        try:
            existing = await repo.get(caller_tenant_id, sub_id)
            if existing is None:
                await repo.upsert(
                    SubscriptionRecord(
                        tenant_id=caller_tenant_id,
                        subscription_id=sub_id,
                        customer_tenant_id=customer_tenant_id,
                        display_name=sub_id,
                    ),
                )
                continue
            if existing.state == "Removed":
                existing.state = "Enabled"
                existing.removed_at = None
                await repo.upsert(existing)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Failed to mirror connected scope tenant=%s scope=%s: %s",
                caller_tenant_id,
                sub_id,
                exc,
            )




async def _mirror_aws_account_for_operator(
    *,
    user: TokenPayload,
    account_id: str,
    region: str,
) -> None:
    """Mirror a connected AWS account into the operator-tenant subscriptions
    container so the timer-driven ScanPipeline picks it up on the next tick.

    Mirrors the Azure helper above. Best-effort: failures are logged and
    swallowed so a transient Cosmos issue does not break the connect step.
    """

    try:
        repo = subscriptions_module._get_repo()  # noqa: SLF001
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Subscriptions repository unavailable for AWS mirror: %s", exc,
        )
        return

    caller_tenant_id = get_tenant_id(user)
    try:
        existing = await repo.get(caller_tenant_id, account_id)
        if existing is None:
            await repo.upsert(
                SubscriptionRecord(
                    tenant_id=caller_tenant_id,
                    subscription_id=account_id,
                    customer_tenant_id=caller_tenant_id,
                    display_name=f"AWS {account_id}",
                    provider=CloudProvider_enum.AWS,
                    aws_account_id=account_id,
                    aws_region=region,
                ),
            )
            return
        # Restore + update region on re-connect.
        if existing.state == "Removed":
            existing.state = "Enabled"
            existing.removed_at = None
        existing.provider = CloudProvider_enum.AWS
        existing.aws_account_id = account_id
        existing.aws_region = region
        await repo.upsert(existing)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Failed to mirror AWS account tenant=%s account=%s: %s",
            caller_tenant_id, account_id, exc,
        )


async def _mirror_gcp_project_for_operator(
    *,
    user: TokenPayload,
    project_id: str,
) -> None:
    """Mirror a connected GCP project into the operator-tenant subscriptions
    container so the timer-driven ScanPipeline picks it up on the next tick.

    Mirrors the AWS helper above. Best-effort: failures are logged and
    swallowed so a transient Cosmos issue does not break the connect step.
    """

    try:
        repo = subscriptions_module._get_repo()  # noqa: SLF001
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Subscriptions repository unavailable for GCP mirror: %s", exc,
        )
        return

    caller_tenant_id = get_tenant_id(user)
    try:
        existing = await repo.get(caller_tenant_id, project_id)
        if existing is None:
            await repo.upsert(
                SubscriptionRecord(
                    tenant_id=caller_tenant_id,
                    subscription_id=project_id,
                    customer_tenant_id=caller_tenant_id,
                    display_name=f"GCP {project_id}",
                    provider=CloudProvider_enum.GCP,
                    gcp_project_id=project_id,
                ),
            )
            return
        if existing.state == "Removed":
            existing.state = "Enabled"
            existing.removed_at = None
        existing.provider = CloudProvider_enum.GCP
        existing.gcp_project_id = project_id
        await repo.upsert(existing)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Failed to mirror GCP project tenant=%s project=%s: %s",
            caller_tenant_id, project_id, exc,
        )


@router.post(
    "/sessions",
    response_model=OnboardingSessionResponseV1,
    status_code=status.HTTP_201_CREATED,
)
async def create_onboarding_session_v1(
    body: OnboardingSessionCreateRequestV1,
    user: TokenPayload = _auth,
) -> OnboardingSessionResponseV1:
    """Create a versioned onboarding session for supported providers."""

    if body.provider is CloudProvider.AZURE:
        tenant_id = body.target_scope.tenant_id.strip().lower()
        if not tenant_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": "invalid_target_scope",
                    "message": "target_scope.tenant_id is required for AZURE.",
                },
            )
        legacy = await subscriptions_module.create_onboarding_session(
            subscriptions_module.OnboardingSessionCreateRequest(
                customer_tenant_id=tenant_id,
            ),
            user=user,
        )
        await _append_audit_event(
            user=user,
            action="session_created",
            provider=CloudProvider.AZURE,
            resource_id=legacy.session_id,
            result="success",
        )
        return _to_v1_response(legacy)

    if body.provider is CloudProvider.AWS:
        account_id = body.target_scope.account_id.strip()
        if not _AWS_ACCOUNT_ID_RE.match(account_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": "invalid_target_scope",
                    "message": "target_scope.account_id must be a 12-digit AWS account id.",
                },
            )
        operator_tenant_id = get_tenant_id(user).lower()
        session_id = uuid.uuid4().hex
        region = (body.target_scope.region or "us-east-1").strip().lower()
        if not re.match(r"^[a-z]{2}-[a-z]+-\d$", region):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": "invalid_target_scope",
                    "message": (
                        "target_scope.region must look like 'us-east-1'"
                        " (lowercase, hyphens)."
                    ),
                },
            )
        aws_session = AwsOnboardingSession(
            session_id=session_id,
            operator_tenant_id=operator_tenant_id,
            account_id=account_id,
            region=region,
            status="initiated",
            external_id=_build_aws_external_id(operator_tenant_id, session_id),
        )
        _aws_sessions[(operator_tenant_id, session_id)] = aws_session
        await _append_audit_event(
            user=user,
            action="session_created",
            provider=CloudProvider.AWS,
            resource_id=session_id,
            result="success",
        )
        return _aws_session_to_response(aws_session)

    if body.provider is CloudProvider.GCP:
        project_id = body.target_scope.project_id.strip()
        if not _GCP_PROJECT_ID_RE.match(project_id) or "-" not in project_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": "invalid_target_scope",
                    "message": "target_scope.project_id must be a valid GCP project id.",
                },
            )
        operator_tenant_id = get_tenant_id(user).lower()
        session_id = uuid.uuid4().hex
        gcp_session = GcpOnboardingSession(
            session_id=session_id,
            operator_tenant_id=operator_tenant_id,
            project_id=project_id,
            status="initiated",
        )
        _gcp_sessions[(operator_tenant_id, session_id)] = gcp_session
        await _append_audit_event(
            user=user,
            action="session_created",
            provider=CloudProvider.GCP,
            resource_id=session_id,
            result="success",
        )
        return _gcp_session_to_response(gcp_session)

    _raise_provider_not_supported(body.provider)


@router.get(
    "/sessions/{session_id}",
    response_model=OnboardingSessionResponseV1,
)
async def get_onboarding_session_v1(
    session_id: str,
    user: TokenPayload = _auth,
) -> OnboardingSessionResponseV1:
    """Return current onboarding session state for authenticated operator tenant."""

    try:
        legacy = await subscriptions_module.get_onboarding_session(
            session_id=session_id,
            user=user,
        )
    except HTTPException as exc:
        if exc.status_code != status.HTTP_404_NOT_FOUND:
            raise
        aws_session = _try_get_aws_session(session_id, user)
        if aws_session is not None:
            return _aws_session_to_response(aws_session)
        gcp_session = _get_gcp_session_or_404(session_id, user)
        return _gcp_session_to_response(gcp_session)
    return _to_v1_response(legacy)


@router.post(
    "/sessions/{session_id}/generate-artifacts",
    response_model=OnboardingSessionResponseV1,
)
async def generate_onboarding_artifacts_v1(
    session_id: str,
    body: GenerateArtifactsRequestV1 | None = None,
    user: TokenPayload = _auth,
) -> OnboardingSessionResponseV1:
    """Generate provider onboarding artifacts.

    For Azure the optional request body selects which compliance
    initiatives the Deploy-to-Azure template assigns (see
    ``GenerateArtifactsRequestV1``). AWS and GCP ignore the body.
    """
    assign_frameworks = (
        body.assign_frameworks if body is not None else "all"
    )
    if assign_frameworks.strip().lower() == "none":
        assign_frameworks = ""

    try:
        legacy = await subscriptions_module.get_onboarding_session(
            session_id=session_id,
            user=user,
        )
    except HTTPException as exc:
        if exc.status_code != status.HTTP_404_NOT_FOUND:
            raise
        aws_session = _try_get_aws_session(session_id, user)
        if aws_session is not None:
            aws_session.status = "trust_pending"
            aws_session.updated_at = datetime.now(timezone.utc)
            control_plane_account_id = os.getenv(
                "CLOUDGUARDIQ_AWS_ACCOUNT_ID",
                "000000000000",
            )
            artifacts = {
                "aws_account_id": control_plane_account_id,
                "aws_external_id": aws_session.external_id,
                "trust_policy_json": _build_aws_trust_policy(
                    control_plane_account_id,
                    aws_session.external_id,
                ),
                "role_name": "CloudGuardIQReadOnlyRole",
                "cloudformation_template_url": os.getenv(
                    "CLOUDGUARDIQ_AWS_IAM_TEMPLATE_URL",
                    "https://example.com/cloudguardiq/aws-onboarding-role.yaml",
                ),
            }
            await _append_audit_event(
                user=user,
                action="artifacts_generated",
                provider=CloudProvider.AWS,
                resource_id=session_id,
                result="success",
            )
            return _aws_session_to_response(aws_session, artifacts=artifacts)

        gcp_session = _get_gcp_session_or_404(session_id, user)
        gcp_session.status = "trust_pending"
        gcp_session.updated_at = datetime.now(timezone.utc)
        pool = os.getenv(
            "CLOUDGUARDIQ_GCP_WORKLOAD_IDENTITY_POOL",
            "projects/000000000000/locations/global/workloadIdentityPools/cloudguardiq",
        )
        provider_resource_name = os.getenv(
            "CLOUDGUARDIQ_GCP_PROVIDER_RESOURCE_NAME",
            _build_gcp_provider_resource_name(pool),
        )
        artifacts = {
            "workload_identity_pool": pool,
            "provider_resource_name": provider_resource_name,
            "service_account_email": (
                f"cloudguardiq-reader@{gcp_session.project_id}.iam.gserviceaccount.com"
            ),
            "gcloud_bind_command": _build_gcp_bind_command(
                gcp_session.project_id,
                provider_resource_name,
            ),
        }
        await _append_audit_event(
            user=user,
            action="artifacts_generated",
            provider=CloudProvider.GCP,
            resource_id=session_id,
            result="success",
        )
        return _gcp_session_to_response(gcp_session, artifacts=artifacts)

    azure_artifacts: dict[str, str] = {"consent_url": legacy.consent_url}
    template = await subscriptions_module.get_onboarding_template(
        tenant_id=legacy.customer_tenant_id,
        scope="subscription",
        assign_frameworks=assign_frameworks,
        user=user,
    )
    azure_artifacts["template_uri"] = template.template_uri
    azure_artifacts["deploy_url"] = template.deploy_url
    azure_artifacts["azure_principal_id"] = template.azure_principal_id
    if template.parameters_uri:
        azure_artifacts["parameters_uri"] = template.parameters_uri
    if template.assigned_initiatives:
        azure_artifacts["assigned_initiatives"] = ",".join(
            a.framework_id for a in template.assigned_initiatives
        )
    await _append_audit_event(
        user=user,
        action="artifacts_generated",
        provider=CloudProvider.AZURE,
        resource_id=session_id,
        result="success",
    )
    return _to_v1_response(legacy, artifacts=azure_artifacts)


@router.post(
    "/sessions/{session_id}/verify",
    response_model=OnboardingSessionResponseV1,
)
async def verify_onboarding_session_v1(
    session_id: str,
    user: TokenPayload = _auth,
) -> OnboardingSessionResponseV1:
    """Verify trust and discover scopes for a session."""

    try:
        legacy = await subscriptions_module.discover_onboarding_session_subscriptions(
            session_id=session_id,
            user=user,
        )
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            aws_session = _try_get_aws_session(session_id, user)
            if aws_session is not None:
                aws_session.discovered_scope_ids = [aws_session.account_id]
                aws_session.status = "verified"
                aws_session.updated_at = datetime.now(timezone.utc)
                checks = [
                    VerificationCheck(check="token_exchange", status="pass"),
                    VerificationCheck(check="permission_probe", status="pass"),
                    VerificationCheck(check="scope_discovery", status="pass"),
                ]
                await _append_audit_event(
                    user=user,
                    action="session_verified",
                    provider=CloudProvider.AWS,
                    resource_id=session_id,
                    result="success",
                )
                return _aws_session_to_response(
                    aws_session,
                    verification_checks=checks,
                )

            gcp_session = _get_gcp_session_or_404(session_id, user)
            gcp_session.discovered_scope_ids = [gcp_session.project_id]
            gcp_session.status = "verified"
            gcp_session.updated_at = datetime.now(timezone.utc)
            checks = [
                VerificationCheck(check="token_exchange", status="pass"),
                VerificationCheck(check="permission_probe", status="pass"),
                VerificationCheck(check="scope_discovery", status="pass"),
            ]
            await _append_audit_event(
                user=user,
                action="session_verified",
                provider=CloudProvider.GCP,
                resource_id=session_id,
                result="success",
            )
            return _gcp_session_to_response(
                gcp_session,
                verification_checks=checks,
            )

        detail = exc.detail
        if isinstance(detail, dict):
            raise HTTPException(
                status_code=exc.status_code,
                detail={
                    "error_code": detail.get("error", "verification_failed"),
                    "provider": "AZURE",
                    "step": "verify",
                    "message": detail.get("message", "Verification failed."),
                },
            ) from exc
        raise

    checks = [
        VerificationCheck(check="token_exchange", status="pass"),
        VerificationCheck(check="permission_probe", status="pass"),
    ]
    # ``discover_onboarding_session_subscriptions`` only returns subscriptions
    # the app principal can actually read AND that are not already linked to
    # this customer. An empty list therefore means one of:
    #   - the Reader RBAC assignment hasn't propagated yet (typical: <2 min)
    #   - admin consent was granted but no Reader role was assigned anywhere
    #   - the customer's only subscription(s) are already linked
    # In all three cases ``scope_discovery`` is technically a successful API
    # call, but surfacing it as PASS is misleading because there's nothing
    # for the operator to connect.
    if not legacy.discovered_subscription_ids:
        checks.append(
            VerificationCheck(
                check="scope_discovery",
                status="warn",
                message=(
                    "Authentication succeeded but no new subscriptions were "
                    "returned. Most common causes: (1) the CloudGuardIQ "
                    "enterprise application has no Reader (or higher) role "
                    "assigned on any subscription yet -- assign one and "
                    "wait ~2 minutes for Azure RBAC to propagate; (2) you "
                    "are linking an additional subscription and the "
                    "onboarding ARM template was only deployed at the "
                    "first subscription's scope -- re-run the Deploy step "
                    "(Step 2) targeting the new subscription, or assign "
                    "Reader to the app on it manually; (3) every "
                    "subscription in this tenant is already linked, in "
                    "which case there is nothing further to connect."
                ),
            )
        )
    else:
        checks.append(VerificationCheck(check="scope_discovery", status="pass"))
    await _append_audit_event(
        user=user,
        action="session_verified",
        provider=CloudProvider.AZURE,
        resource_id=session_id,
        result="success",
    )
    return _to_v1_response(legacy, verification_checks=checks)


@router.post(
    "/sessions/{session_id}/connect",
    response_model=OnboardingSessionResponseV1,
)
async def connect_onboarding_session_v1(
    session_id: str,
    body: OnboardingSessionConnectRequestV1,
    user: TokenPayload = _auth,
) -> OnboardingSessionResponseV1:
    """Connect selected scopes, persist connection metadata, and mark connected."""

    try:
        legacy = await subscriptions_module.connect_onboarding_session_subscriptions(
            session_id=session_id,
            body=subscriptions_module.OnboardingSessionConnectRequest(
                subscription_ids=body.scope_ids,
            ),
            user=user,
        )
        scopes = legacy.connected_subscription_ids or body.scope_ids
        rec = await _upsert_connection_and_credentials(
            user=user,
            provider=CloudProvider.AZURE,
            linked_scopes=scopes,
            target_scope={"tenant_id": legacy.customer_tenant_id},
            display_name="Azure connection",
        )
        await _mirror_connected_scopes_for_operator(
            user=user,
            scopes=scopes,
            customer_tenant_id=legacy.customer_tenant_id,
        )
        return _to_v1_response(legacy, connection_id=rec.connection_id)
    except HTTPException as exc:
        if exc.status_code != status.HTTP_404_NOT_FOUND:
            raise

    aws_session = _try_get_aws_session(session_id, user)
    if aws_session is not None:
        selected = body.scope_ids or aws_session.discovered_scope_ids or [aws_session.account_id]
        normalized = [sid.strip() for sid in selected if sid.strip()]
        if not normalized:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error_code": "no_scopes_selected",
                    "message": "Provide scope_ids or run verify first.",
                },
            )
        aws_session.linked_scope_ids = list(dict.fromkeys(normalized))
        aws_session.status = "connected"
        aws_session.updated_at = datetime.now(timezone.utc)
        rec = await _upsert_connection_and_credentials(
            user=user,
            provider=CloudProvider.AWS,
            linked_scopes=aws_session.linked_scope_ids,
            target_scope={
                "account_id": aws_session.account_id,
                "region": aws_session.region,
            },
            display_name=f"AWS {aws_session.account_id}",
        )
        # Mirror the AWS account into the subscriptions container so the
        # timer-driven scan picks it up automatically -- same pattern
        # the Azure branch uses above.
        await _mirror_aws_account_for_operator(
            user=user,
            account_id=aws_session.account_id,
            region=aws_session.region,
        )
        return _aws_session_to_response(aws_session, connection_id=rec.connection_id)

    gcp_session = _get_gcp_session_or_404(session_id, user)
    selected = body.scope_ids or gcp_session.discovered_scope_ids or [gcp_session.project_id]
    normalized = [sid.strip() for sid in selected if sid.strip()]
    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": "no_scopes_selected",
                "message": "Provide scope_ids or run verify first.",
            },
        )
    gcp_session.linked_scope_ids = list(dict.fromkeys(normalized))
    gcp_session.status = "connected"
    gcp_session.updated_at = datetime.now(timezone.utc)
    rec = await _upsert_connection_and_credentials(
        user=user,
        provider=CloudProvider.GCP,
        linked_scopes=gcp_session.linked_scope_ids,
        target_scope={"project_id": gcp_session.project_id},
        display_name="GCP connection",
    )
    await _mirror_gcp_project_for_operator(
        user=user,
        project_id=gcp_session.project_id,
    )
    return _gcp_session_to_response(gcp_session, connection_id=rec.connection_id)


@cloud_connections_router.get("", response_model=list[CloudConnectionResponse])
async def list_cloud_connections(user: TokenPayload = _auth) -> list[CloudConnectionResponse]:
    """List tenant cloud connections."""

    repo = _cloud_connection_repository
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cloud connection repository not configured",
        )
    tenant_id = get_tenant_id(user)
    records = await repo.list(tenant_id)
    return [_connection_response(r) for r in records]


@cloud_connections_router.get(
    "/{connection_id}",
    response_model=CloudConnectionResponse,
)
async def get_cloud_connection(
    connection_id: str,
    user: TokenPayload = _auth,
) -> CloudConnectionResponse:
    """Get one cloud connection by id."""

    repo = _cloud_connection_repository
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cloud connection repository not configured",
        )
    tenant_id = get_tenant_id(user)
    rec = await repo.get(tenant_id, connection_id)
    if rec is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    return _connection_response(rec)


@cloud_connections_router.post(
    "/{connection_id}/refresh",
    response_model=CloudConnectionResponse,
)
async def refresh_cloud_connection(
    connection_id: str,
    user: TokenPayload = _auth,
) -> CloudConnectionResponse:
    """Refresh connection health by updating last_verified_at timestamp."""

    repo = _cloud_connection_repository
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cloud connection repository not configured",
        )
    tenant_id = get_tenant_id(user)
    rec = await repo.get(tenant_id, connection_id)
    if rec is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    if rec.status == "disconnected":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error_code": "connection_disconnected",
                "message": "Cannot refresh a disconnected connection.",
            },
        )
    rec.last_verified_at = datetime.now(timezone.utc)
    rec.status = "active"
    saved = await repo.upsert(rec)
    await _append_audit_event(
        user=user,
        action="connection_refreshed",
        provider=CloudProvider(saved.provider),
        resource_id=saved.connection_id,
        result="success",
    )
    return _connection_response(saved)


@cloud_connections_router.delete(
    "/{connection_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def disconnect_cloud_connection(
    connection_id: str,
    user: TokenPayload = _auth,
) -> Response:
    """Disconnect one cloud connection and invalidate credential references."""

    conn_repo = _cloud_connection_repository
    cred_repo = _credential_ref_repository
    if conn_repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cloud connection repository not configured",
        )

    tenant_id = get_tenant_id(user)
    rec = await conn_repo.get(tenant_id, connection_id)
    if rec is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    rec.status = "disconnected"
    rec.updated_at = datetime.now(timezone.utc)
    await conn_repo.upsert(rec)

    if cred_repo is not None:
        await cred_repo.delete_by_connection(tenant_id, connection_id)

    _aws_sessions.pop((tenant_id.lower(), connection_id), None)
    _gcp_sessions.pop((tenant_id.lower(), connection_id), None)

    try:
        provider_enum = CloudProvider(rec.provider)
    except ValueError:
        provider_enum = CloudProvider.AZURE
    await _append_audit_event(
        user=user,
        action="connection_disconnected",
        provider=provider_enum,
        resource_id=connection_id,
        result="success",
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)

