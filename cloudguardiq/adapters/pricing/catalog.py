"""CloudGuardIQ -- baseline list-price catalog for AWS and GCP FinOps.

This is **not** a billing-API integration. It is a curated map of public
list prices (us-east-1 / us-central1, USD, on-demand) used to stamp
``ResourceSnapshot.cost_monthly`` during a Tier-1 native scan so that the
FinOps rule pack ("unattached disk", "unattached EIP", etc.) can emit a
meaningful ``waste_monthly_usd`` value.

Why a catalog instead of a live billing API
-------------------------------------------
* AWS Cost Explorer / GCP Cloud Billing require extra permissions and a
  per-tenant export/dataset that we cannot assume is present on the
  first scan.
* For *waste* detection (the only place FinOps rules need cost today)
  list prices are a strong lower bound: an unattached disk is wasting
  *at least* its provisioned-storage list price regardless of any
  committed-use discount the customer has negotiated.
* Real, customer-specific costs can layer on later as a Tier-2
  enrichment step (mirror of ``AzureAdapter._fetch_cost_data``) without
  changing the rule contract.

All prices are **monthly USD**, computed at 730 hours / month.

Sources (verified May 2026):
* AWS EBS pricing -- https://aws.amazon.com/ebs/pricing/
* AWS Elastic IP -- https://aws.amazon.com/vpc/pricing/ (idle public IPv4)
* GCP Persistent Disk -- https://cloud.google.com/compute/disks-image-pricing
"""

from __future__ import annotations

_HOURS_PER_MONTH = 730.0


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

# Per-GB-month list price, us-east-1.
_AWS_EBS_PRICE_PER_GB_MONTH: dict[str, float] = {
    "gp3": 0.08,
    "gp2": 0.10,
    "io2": 0.125,
    "io1": 0.125,
    "st1": 0.045,
    "sc1": 0.015,
    "standard": 0.05,
}
_AWS_EBS_DEFAULT_PRICE = 0.10  # Fall back to gp2 list price.

# AWS now bills every public IPv4 address at $0.005/hour whether attached
# or not (effective Feb 2024). For *unattached* EIPs this is pure waste.
_AWS_PUBLIC_IPV4_HOURLY_USD = 0.005


def aws_ebs_monthly_usd(volume_type: str | None, size_gb: int | float | None) -> float:
    """Return the list-price monthly cost (USD) for an EBS volume.

    Args:
        volume_type: One of gp3 / gp2 / io1 / io2 / st1 / sc1 / standard.
            Unknown / ``None`` types fall back to the gp2 list price.
        size_gb: Provisioned size in GiB.

    Returns:
        Monthly cost in USD. ``0.0`` when *size_gb* is missing or zero.
    """
    if not size_gb:
        return 0.0
    key = (volume_type or "").strip().lower()
    per_gb = _AWS_EBS_PRICE_PER_GB_MONTH.get(key, _AWS_EBS_DEFAULT_PRICE)
    return round(float(size_gb) * per_gb, 2)


def aws_eip_unattached_monthly_usd() -> float:
    """Return the list-price monthly cost (USD) of an idle Elastic IP."""
    return round(_AWS_PUBLIC_IPV4_HOURLY_USD * _HOURS_PER_MONTH, 2)


# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------

# Per-GB-month list price, us-central1.
_GCP_PD_PRICE_PER_GB_MONTH: dict[str, float] = {
    "pd-standard": 0.04,
    "pd-balanced": 0.10,
    "pd-ssd": 0.17,
    "pd-extreme": 0.125,  # capacity portion only; ignores provisioned IOPS
    "hyperdisk-balanced": 0.12,
}
_GCP_PD_DEFAULT_PRICE = 0.10  # Fall back to pd-balanced.


def gcp_persistent_disk_monthly_usd(
    disk_type: str | None,
    size_gb: int | float | None,
) -> float:
    """Return the list-price monthly cost (USD) for a Compute Engine disk.

    Args:
        disk_type: ``pd-standard`` / ``pd-balanced`` / ``pd-ssd`` /
            ``pd-extreme`` / ``hyperdisk-balanced``. Unknown / ``None``
            types fall back to ``pd-balanced``.
        size_gb: Provisioned size in GiB.

    Returns:
        Monthly cost in USD. ``0.0`` when *size_gb* is missing or zero.
    """
    if not size_gb:
        return 0.0
    key = (disk_type or "").strip().lower()
    per_gb = _GCP_PD_PRICE_PER_GB_MONTH.get(key, _GCP_PD_DEFAULT_PRICE)
    return round(float(size_gb) * per_gb, 2)
