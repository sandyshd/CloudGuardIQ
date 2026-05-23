"""Tests for the AWS/GCP list-price catalog."""

from __future__ import annotations

import pytest

from cloudguardiq.adapters.pricing import (
    aws_ebs_monthly_usd,
    aws_eip_unattached_monthly_usd,
    gcp_persistent_disk_monthly_usd,
)

# ---------------------------------------------------------------------------
# AWS EBS
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vol_type,size_gb,expected",
    [
        ("gp3", 100, 8.0),
        ("gp2", 100, 10.0),
        ("io2", 200, 25.0),
        ("st1", 500, 22.5),
        ("sc1", 1000, 15.0),
    ],
)
def test_aws_ebs_monthly_usd_known_types(vol_type, size_gb, expected) -> None:
    """List-price math matches the published AWS pricing page."""
    assert aws_ebs_monthly_usd(vol_type, size_gb) == pytest.approx(expected)


def test_aws_ebs_monthly_usd_unknown_type_falls_back_to_gp2() -> None:
    """Unknown volume types fall back to the gp2 list price."""
    assert aws_ebs_monthly_usd("MoonStorage", 100) == pytest.approx(10.0)


@pytest.mark.parametrize("size", [0, None])
def test_aws_ebs_monthly_usd_zero_size_returns_zero(size) -> None:
    """A missing/zero size must short-circuit to 0.0 (no division-by-anything)."""
    assert aws_ebs_monthly_usd("gp3", size) == 0.0


# ---------------------------------------------------------------------------
# AWS EIP
# ---------------------------------------------------------------------------


def test_aws_eip_unattached_monthly_is_3_dot_65() -> None:
    """0.005 * 730 == 3.65 USD/month (post-Feb-2024 IPv4 charge)."""
    assert aws_eip_unattached_monthly_usd() == pytest.approx(3.65)


# ---------------------------------------------------------------------------
# GCP Persistent Disk
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "disk_type,size_gb,expected",
    [
        ("pd-standard", 100, 4.0),
        ("pd-balanced", 100, 10.0),
        ("pd-ssd", 100, 17.0),
    ],
)
def test_gcp_pd_monthly_usd_known_types(disk_type, size_gb, expected) -> None:
    """List-price math matches the published GCP pricing page."""
    assert gcp_persistent_disk_monthly_usd(disk_type, size_gb) == pytest.approx(expected)


def test_gcp_pd_unknown_type_falls_back_to_balanced() -> None:
    """Unknown disk types fall back to pd-balanced list price."""
    assert gcp_persistent_disk_monthly_usd("pd-future", 100) == pytest.approx(10.0)


@pytest.mark.parametrize("size", [0, None])
def test_gcp_pd_zero_size_returns_zero(size) -> None:
    """Missing/zero size short-circuits to 0.0."""
    assert gcp_persistent_disk_monthly_usd("pd-ssd", size) == 0.0
