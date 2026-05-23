"""CloudGuardIQ -- GCP FinOps (waste detection) rule pack.

The core unattached-disk rule lives in ``compute.py`` next to the disk
snapshot logic. This module is kept as a stable import point in case
new GCP FinOps rules are added later.
"""

from __future__ import annotations

__all__: list[str] = []
