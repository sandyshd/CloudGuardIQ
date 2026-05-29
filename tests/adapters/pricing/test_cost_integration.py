"""Integration tests: list-price cost flows from adapter into FinOps rules.

These tests do not call AWS or GCP. They construct an adapter, invoke
``_snapshot()`` with the same kwargs the real scanners use, and assert
that the resulting ``ResourceSnapshot.cost_monthly`` lights up the
``waste_monthly_usd`` field of the matching FinOps rule.
"""

from __future__ import annotations

import pytest

from cloudguardiq.adapters.aws.adapter import AWSAdapter
from cloudguardiq.adapters.gcp.adapter import GCPAdapter
from cloudguardiq.adapters.pricing import (
    aws_ebs_monthly_usd,
    aws_eip_unattached_monthly_usd,
    gcp_persistent_disk_monthly_usd,
)
from cloudguardiq.adapters.rules.aws.ec2 import UnattachedEbsVolumeRule
from cloudguardiq.adapters.rules.aws.finops import UnattachedEipRule
from cloudguardiq.adapters.rules.gcp.compute import UnattachedDiskRule

# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------


def test_aws_unattached_ebs_volume_carries_list_price() -> None:
    """An unattached gp3 100GB volume should waste $8/mo (gp3 list price)."""
    adapter = AWSAdapter(account_id="111122223333", region="us-east-1")
    snap = adapter._snapshot(  # noqa: SLF001
        resource_type="AWS::EC2::Volume",
        resource_name="vol-abc",
        region="us-east-1",
        config={
            "encrypted": True,
            "state": "available",  # unattached
            "size": 100,
            "attachments": [],
            "volume_type": "gp3",
        },
        cost_monthly=aws_ebs_monthly_usd("gp3", 100),
    )
    assert snap.cost_monthly == pytest.approx(8.0)

    finding = UnattachedEbsVolumeRule().evaluate(snap)
    assert finding is not None
    assert finding.waste_monthly_usd == pytest.approx(8.0)


def test_aws_unattached_eip_carries_idle_ipv4_price() -> None:
    """An unassociated EIP wastes the post-Feb-2024 idle-IPv4 charge."""
    adapter = AWSAdapter(account_id="111122223333", region="us-east-1")
    snap = adapter._snapshot(  # noqa: SLF001
        resource_type="AWS::EC2::EIP",
        resource_name="eipalloc-1",
        region="us-east-1",
        config={"association_id": None, "public_ip": "3.3.3.3", "domain": "vpc"},
        cost_monthly=aws_eip_unattached_monthly_usd(),
    )
    finding = UnattachedEipRule().evaluate(snap)
    assert finding is not None
    assert finding.waste_monthly_usd == pytest.approx(3.65)


def test_aws_attached_eip_has_zero_waste() -> None:
    """An EIP attached to a NIC must report 0 waste even though AWS bills it."""
    adapter = AWSAdapter(account_id="111122223333", region="us-east-1")
    snap = adapter._snapshot(  # noqa: SLF001
        resource_type="AWS::EC2::EIP",
        resource_name="eipalloc-2",
        region="us-east-1",
        config={
            "association_id": "eipassoc-1",
            "public_ip": "3.3.3.4",
            "domain": "vpc",
        },
        cost_monthly=0.0,
    )
    assert UnattachedEipRule().evaluate(snap) is None


# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------


def test_gcp_unattached_pd_ssd_carries_list_price() -> None:
    """An unattached 500GB pd-ssd should waste $85/mo (500 * $0.17)."""
    adapter = GCPAdapter(project_id="my-proj-123")
    snap = adapter._snapshot(  # noqa: SLF001
        resource_type="google.compute.Disk",
        resource_name="orphan-disk",
        region="us-central1",
        config={
            "size_gb": 500,
            "status": "READY",
            "users": [],  # unattached
            "cmek_encrypted": True,
            "type": "pd-ssd",
        },
        cost_monthly=gcp_persistent_disk_monthly_usd("pd-ssd", 500),
    )
    assert snap.cost_monthly == pytest.approx(85.0)

    finding = UnattachedDiskRule().evaluate(snap)
    assert finding is not None
    assert finding.waste_monthly_usd == pytest.approx(85.0)
