"""CloudGuardIQ — Cloud-agnostic adapter factory.

Single entry point used by the scan pipeline (and tests) to build the
right ``AdapterBase`` implementation for a given cloud connection. Keeps
provider-specific construction logic (Azure ``DefaultAzureCredential``
vs AWS ``boto3.Session``) out of the pipeline orchestrator.
"""

from __future__ import annotations

import logging
from typing import Any

from cloudguardiq.adapters.base import AdapterBase
from cloudguardiq.core.enums import CloudProvider

logger = logging.getLogger(__name__)


class UnsupportedProviderError(RuntimeError):
    """Raised when no adapter is available for the requested provider."""


def build_scan_adapter(
    provider: CloudProvider | str,
    *,
    # Azure params
    subscription_id: str | None = None,
    credential: Any | None = None,
    async_credential: Any | None = None,
    db: Any | None = None,
    # AWS params
    account_id: str | None = None,
    region: str | None = None,
    boto3_session: Any | None = None,
) -> AdapterBase:
    """Return an ``AdapterBase`` for the given provider.

    Args:
        provider: ``CloudProvider`` enum value or its string name.
        subscription_id: Azure subscription id (required for AZURE).
        credential: Synchronous Azure ``TokenCredential``.
        async_credential: Async Azure ``TokenCredential``.
        db: Optional ``CosmosRepository`` (Azure only).
        account_id: AWS account id (required for AWS).
        region: Default AWS region (defaults to ``us-east-1``).
        boto3_session: Pre-built ``boto3.Session`` (mainly for tests).

    Raises:
        UnsupportedProviderError: When *provider* is unknown or required
            parameters are missing.
    """
    provider_enum = (
        provider if isinstance(provider, CloudProvider) else CloudProvider(str(provider))
    )

    if provider_enum is CloudProvider.AZURE:
        from cloudguardiq.adapters.azure_adapter import AzureAdapter

        if not subscription_id or credential is None:
            raise UnsupportedProviderError(
                "AZURE adapter requires subscription_id and credential"
            )
        return AzureAdapter(
            credential=credential,
            subscription_id=subscription_id,
            db=db,
            async_credential=async_credential,
        )

    if provider_enum is CloudProvider.AWS:
        from cloudguardiq.adapters.aws.adapter import AWSAdapter

        if not account_id:
            raise UnsupportedProviderError("AWS adapter requires account_id")
        return AWSAdapter(
            account_id=account_id,
            region=region or "us-east-1",
            session=boto3_session,
        )

    raise UnsupportedProviderError(
        f"No adapter implementation registered for provider {provider_enum.value}"
    )
