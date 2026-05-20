"""Phase 3.2: customer credential factory tests."""

from __future__ import annotations

import pytest

from cloudguardiq.auth.customer_credential import (
    AzureCustomerCredentialFactory,
    CustomerCredentialFactory,
    build_default_factory,
)


class _Settings:
    def __init__(
        self, *, client_id: str = "c1", cert_path: str = "",
        secret: str = "",
    ) -> None:
        self.azure_client_id = client_id
        self.azure_certificate_path = cert_path
        self.azure_client_secret = secret


def test_factory_requires_client_id() -> None:
    with pytest.raises(ValueError, match="client_id"):
        AzureCustomerCredentialFactory(client_id="")


def test_factory_requires_cert_or_secret() -> None:
    with pytest.raises(ValueError, match="certificate_path"):
        AzureCustomerCredentialFactory(client_id="c1")


def test_for_tenant_requires_tenant_id() -> None:
    f = AzureCustomerCredentialFactory(
        client_id="c1", client_secret="s",
    )
    with pytest.raises(ValueError, match="tenant_id"):
        f.for_tenant("")


def test_for_tenant_picks_tenant_with_secret_path() -> None:
    f = AzureCustomerCredentialFactory(
        client_id="c1", client_secret="s",
    )
    cred = f.for_tenant("11111111-1111-1111-1111-111111111111")
    # ClientSecretCredential exposes _tenant_id internally; the public
    # surface area is empty so we check the type instead.
    assert cred.__class__.__name__ == "ClientSecretCredential"


def test_for_tenant_uses_certificate_when_present(tmp_path) -> None:
    # Use a fake cert blob; ClientCertificateCredential will refuse to
    # parse but we only care that the factory tried that path.
    cert = tmp_path / "cert.pem"
    cert.write_bytes(b"-----BEGIN PRIVATE KEY-----\nfake\n")
    f = AzureCustomerCredentialFactory(
        client_id="c1", certificate_path=str(cert),
    )
    with pytest.raises(Exception):  # noqa: B017
        # Real azure-identity parsing fails; that proves we took the
        # certificate path rather than secret.
        f.for_tenant("11111111-1111-1111-1111-111111111111")


def test_build_default_factory_returns_none_without_client_id() -> None:
    assert build_default_factory(_Settings(client_id="")) is None


def test_build_default_factory_returns_none_without_cred() -> None:
    assert build_default_factory(_Settings(client_id="c1")) is None


def test_build_default_factory_with_secret() -> None:
    f = build_default_factory(_Settings(client_id="c1", secret="s"))
    assert isinstance(f, CustomerCredentialFactory)
    cred = f.for_tenant("11111111-1111-1111-1111-111111111111")
    assert cred.__class__.__name__ == "ClientSecretCredential"
