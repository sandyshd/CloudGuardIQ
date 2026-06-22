"""CloudGuardIQ -- canonical customer identity (``org_id``) helpers.

``org_id`` is the cloud-neutral customer/tenant scope used as the
partition key for all customer-owned data (findings, snapshots, budgets,
billing, reports, cloud connections). It is deliberately decoupled from
the Azure Entra tenant id (``tid``):

* Microsoft Entra *workforce* logins derive ``org_id`` from their Azure
  ``tid`` (see :func:`derive_org_id_from_tid`).
* Microsoft Entra *External ID* (CIAM) logins -- added in Phase 2 -- mint
  a provider-independent ``org_id`` so AWS/GCP-only customers, who have no
  Azure tenant, can still own data.

The Azure ``tid`` is retained separately (see
:attr:`OrgIdentity.azure_tenant_id`) ONLY to correlate the cross-tenant
credential used to scan a customer''s Azure subscriptions. It must never be
used as the customer data scope.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel

#: Sentinel ``org_id`` used when authentication is disabled (local/dev).
ANONYMOUS_ORG_ID = "anonymous"


def derive_org_id_from_tid(tid: str) -> str:
    """Return the canonical ``org_id`` for an Entra workforce tenant.

    Phase 1 maps the Azure tenant id (``tid``) to ``org_id`` verbatim so
    customer data scopes are stable and provider-agnostic. CIAM logins
    (Phase 2) bypass this and supply their own minted ``org_id``.

    :param tid: The Azure Entra tenant id from a validated token.
    :returns: The canonical ``org_id`` string.
    """
    return tid.strip()


def mint_org_id() -> str:
    """Return a fresh, provider-independent ``org_id``.

    Used the first time a Microsoft Entra External ID (CIAM) user
    signs in. AWS/GCP-only customers have no Azure tenant to derive a
    scope from, so a new opaque 32-char hex GUID is minted and stored
    in the org record. Subsequent logins resolve the same ``org_id``
    from that record.

    :returns: A new 32-character hexadecimal ``org_id``.
    """
    return uuid.uuid4().hex


class OrgIdentity(BaseModel):
    """Resolved customer identity for an authenticated request.

    ``org_id`` is the canonical, cloud-neutral data scope. ``azure_tenant_id``
    is populated only for Entra workforce logins and is used solely for
    Azure cross-tenant scan correlation -- never as the data scope.
    """

    org_id: str
    subject: str = ""
    azure_tenant_id: str = ""
    object_id: str = ""
