"""Storage backends for compliance report PDFs.

``ReportStorage`` is an abstract protocol with two implementations:

* :class:`BlobReportStorage` uses Azure Blob Storage with a short-lived
  user-delegation SAS for the download URL.
* :class:`InMemoryReportStorage` keeps bytes in a process-local dict and
  exposes them through the ``/reports/{id}/download`` API route. Used by
  tests and local/dev mode.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Protocol

logger = logging.getLogger(__name__)


class ReportStorage(Protocol):
    """Protocol every report storage backend must implement."""

    async def upload(self, blob_name: str, data: bytes) -> str:
        """Persist *data* under *blob_name* and return a download URL."""

    async def download(self, blob_name: str) -> bytes | None:
        """Return the raw bytes for *blob_name* or ``None`` if missing."""


class InMemoryReportStorage:
    """Process-local store used by tests and dev mode."""

    def __init__(self, *, download_url_prefix: str = "") -> None:
        self._items: dict[str, bytes] = {}
        self._prefix = download_url_prefix.rstrip("/")

    async def upload(self, blob_name: str, data: bytes) -> str:
        self._items[blob_name] = bytes(data)
        # Callers route bytes back through /reports/{id}/download using the
        # report_id encoded in blob_name; the prefix is purely cosmetic so the
        # frontend can resolve relative API URLs.
        if self._prefix:
            return f"{self._prefix}/{blob_name}"
        return f"memory://{blob_name}"

    async def download(self, blob_name: str) -> bytes | None:
        return self._items.get(blob_name)


class BlobReportStorage:
    """Azure Blob Storage backend with user-delegation SAS downloads."""

    def __init__(
        self,
        *,
        account_url: str,
        container: str,
        sas_expiry_minutes: int = 60,
    ) -> None:
        if not account_url:
            raise ValueError("account_url is required for BlobReportStorage")
        self._account_url = account_url.rstrip("/")
        self._container = container
        self._sas_expiry_minutes = sas_expiry_minutes
        self._client = None  # lazy import so tests don't require the SDK
        self._credential = None
        self._ensured = False

    def _ensure_client(self) -> None:
        if self._client is not None:
            return
        from azure.identity.aio import DefaultAzureCredential
        from azure.storage.blob.aio import BlobServiceClient

        self._credential = DefaultAzureCredential()
        self._client = BlobServiceClient(
            account_url=self._account_url,
            credential=self._credential,
        )

    async def _ensure_container(self) -> None:
        if self._ensured:
            return
        assert self._client is not None
        container = self._client.get_container_client(self._container)
        try:
            await container.create_container()
        except Exception as exc:  # noqa: BLE001
            # 409 ContainerAlreadyExists is the expected happy path.
            logger.debug("Container ensure for %s: %s", self._container, exc)
        self._ensured = True

    async def upload(self, blob_name: str, data: bytes) -> str:
        self._ensure_client()
        await self._ensure_container()
        assert self._client is not None
        blob = self._client.get_blob_client(
            container=self._container, blob=blob_name,
        )
        await blob.upload_blob(
            data,
            overwrite=True,
            content_type="application/pdf",
        )
        return await self._build_sas_url(blob_name)

    async def download(self, blob_name: str) -> bytes | None:
        self._ensure_client()
        assert self._client is not None
        blob = self._client.get_blob_client(
            container=self._container, blob=blob_name,
        )
        try:
            downloader = await blob.download_blob()
            return await downloader.readall()
        except Exception as exc:  # noqa: BLE001
            logger.info("Blob %s not retrievable: %s", blob_name, exc)
            return None

    async def _build_sas_url(self, blob_name: str) -> str:
        """Return a read-only user-delegation SAS URL for *blob_name*."""
        from azure.storage.blob import (
            BlobSasPermissions,
            generate_blob_sas,
        )

        assert self._client is not None
        start = datetime.now(timezone.utc) - timedelta(minutes=5)
        expiry = datetime.now(timezone.utc) + timedelta(
            minutes=self._sas_expiry_minutes,
        )
        user_delegation_key = await self._client.get_user_delegation_key(
            key_start_time=start,
            key_expiry_time=expiry,
        )
        account_name = self._account_url.split("//", 1)[-1].split(".", 1)[0]
        sas = generate_blob_sas(
            account_name=account_name,
            container_name=self._container,
            blob_name=blob_name,
            user_delegation_key=user_delegation_key,
            permission=BlobSasPermissions(read=True),
            expiry=expiry,
            start=start,
        )
        return f"{self._account_url}/{self._container}/{blob_name}?{sas}"

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
        if self._credential is not None:
            await self._credential.close()
