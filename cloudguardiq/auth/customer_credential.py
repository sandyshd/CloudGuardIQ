"""CloudGuardIQ -- per-customer-tenant credential factory (Phase 3.2).

When a customer in a different Entra tenant grants admin consent to the
CloudGuardIQ multi-tenant app, we need an Azure credential that targets
*that* customer's tenant when calling ARM / Resource Graph on their
subscriptions.

This module hides the Azure SDK choice (``ClientCertificateCredential``
preferred, ``ClientSecretCredential`` fallback) behind a small factory
object so the rest of the code base never imports ``azure.identity``
directly for cross-tenant flows.

Tests inject a :class:`StubCustomerCredentialFactory` that records the
``tenant_id`` it was asked to build for; production wires the real
:class:`AzureCustomerCredentialFactory` from app startup.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class CustomerCredentialFactory(ABC):
    """Abstract factory that returns an Azure credential for a tenant."""

    @abstractmethod
    def for_tenant(self, tenant_id: str) -> Any:
        """Return a credential bound to ``tenant_id``.

        Implementations should return an object compatible with the
        ``TokenCredential`` protocol expected by the Azure SDK
        (synchronous ``get_token`` method). Async variants are not
        required because Resource Graph / ARM calls used by the
        access probe and scanner run via ``run_in_executor``.
        """


class AzureCustomerCredentialFactory(CustomerCredentialFactory):
    """Build :class:`ClientCertificateCredential` (or secret fallback).

    The CloudGuardIQ app registration is multi-tenant. Each customer
    tenant sees the same ``client_id`` after admin consent. To call
    their ARM endpoints we authenticate against
    ``login.microsoftonline.com/{customer_tid}`` using either:

    * a client certificate (preferred -- managed in Key Vault), or
    * a client secret (transitional -- already provisioned by Phase 2
      Terraform via ``azuread_application_password``).

    Construction is lazy: nothing is imported from ``azure.identity``
    until :meth:`for_tenant` is called, so unit tests that never
    trigger a real cross-tenant call do not need the SDK installed.
    """

    def __init__(
        self,
        *,
        client_id: str,
        certificate_path: str | None = None,
        certificate_data: bytes | None = None,
        client_secret: str | None = None,
    ) -> None:
        if not client_id:
            raise ValueError("client_id is required")
        if not (certificate_path or certificate_data or client_secret):
            raise ValueError(
                "one of certificate_path, certificate_data, client_secret "
                "is required to build a customer-tenant credential",
            )
        self._client_id = client_id
        self._certificate_path = certificate_path
        self._certificate_data = certificate_data
        self._client_secret = client_secret

    def for_tenant(self, tenant_id: str) -> Any:
        """Return a TokenCredential bound to ``tenant_id``.

        Prefers certificate auth when a certificate is configured;
        falls back to client-secret auth otherwise.
        """
        if not tenant_id:
            raise ValueError("tenant_id is required")

        if self._certificate_path or self._certificate_data:
            from azure.identity import ClientCertificateCredential

            cert_data = self._certificate_data
            if cert_data is None and self._certificate_path:
                cert_data = Path(self._certificate_path).read_bytes()
            return ClientCertificateCredential(
                tenant_id=tenant_id,
                client_id=self._client_id,
                certificate_data=cert_data,
            )

        from azure.identity import ClientSecretCredential

        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=self._client_id,
            client_secret=self._client_secret,
        )


def build_default_factory(settings: Any) -> CustomerCredentialFactory | None:
    """Return a factory wired from :class:`Settings`, or ``None``.

    Returns ``None`` when neither a certificate nor a client secret is
    configured -- the caller should fall back to the local
    :class:`DefaultAzureCredential` (single-tenant / dev mode).
    """
    client_id = getattr(settings, "azure_client_id", "") or ""
    if not client_id:
        return None

    cert_path = getattr(settings, "azure_certificate_path", "") or None
    secret = getattr(settings, "azure_client_secret", "") or None
    if not cert_path and not secret:
        logger.info(
            "No customer credential configured; cross-tenant scans disabled",
        )
        return None
    try:
        return AzureCustomerCredentialFactory(
            client_id=client_id,
            certificate_path=cert_path,
            client_secret=secret,
        )
    except ValueError as exc:
        logger.warning("Customer credential factory unavailable: %s", exc)
        return None
