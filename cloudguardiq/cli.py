"""CloudGuardIQ -- CLI entry point.

Usage:
    python -m cloudguardiq scan --subscription-id <id> --output json|table
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from typing import Any

from cloudguardiq.core.models import FindingResult, ResourceSnapshot

logger = logging.getLogger(__name__)


async def _run_scan(subscription_id: str, output_format: str) -> None:
    """Execute a full tiered scan and print results."""
    from azure.identity import DefaultAzureCredential

    from cloudguardiq.adapters.azure_adapter import AzureAdapter
    from cloudguardiq.adapters.native_scanner import RULE_REGISTRY
    from cloudguardiq.policy.engine import PolicyEngine

    # Build a minimal mock DB for CLI usage (no Cosmos needed)
    db = _StubCosmosRepository()

    credential = DefaultAzureCredential()
    adapter = AzureAdapter(
        credential=credential,
        subscription_id=subscription_id,
        db=db,
    )

    logger.info("Starting scan for subscription %s", subscription_id)
    snapshots = await adapter.scan()
    logger.info("Scan complete: %d snapshots", len(snapshots))

    engine = PolicyEngine()
    for rule in RULE_REGISTRY:
        def _wrap(r=rule):  # noqa: E301
            def _eval(snapshot: ResourceSnapshot) -> list[FindingResult]:
                result = r.evaluate(snapshot)
                if result is None:
                    return []
                if isinstance(result, list):
                    return result
                return [result]
            return _eval
        engine.register_rule(_wrap())

    findings = engine.evaluate(snapshots)
    logger.info("Policy evaluation complete: %d findings", len(findings))

    if output_format == "json":
        result = {
            "subscription_id": subscription_id,
            "snapshots_count": len(snapshots),
            "findings_count": len(findings),
            "findings": [f.model_dump(mode="json") for f in findings],
        }
        print(json.dumps(result, indent=2, default=str))  # noqa: T201
    else:
        _print_table(snapshots, findings)


def _print_table(
    snapshots: list[ResourceSnapshot],
    findings: list[Any],
) -> None:
    """Print a human-readable table of findings."""
    print(f"\n{'='*80}")  # noqa: T201
    print("  CloudGuardIQ Scan Results")  # noqa: T201
    print(f"  Snapshots: {len(snapshots)} | Findings: {len(findings)}")  # noqa: T201
    print(f"{'='*80}\n")  # noqa: T201

    if not findings:
        print("  No findings detected.")  # noqa: T201
        return

    header = f"  {'Rule ID':<15} {'Severity':<12} {'Type':<12} {'Description'}"
    print(header)  # noqa: T201
    print(f"  {'-'*75}")  # noqa: T201
    for f in findings:
        desc = (f.description or f.rule_name)[:50]
        print(f"  {f.rule_id:<15} {f.severity:<12} {f.finding_type:<12} {desc}")  # noqa: T201


class _StubCosmosRepository:
    """Minimal stub so AzureAdapter can work without a real Cosmos DB."""

    async def get_capability_flags(self, sub_id: str) -> None:
        """Return None (no cache)."""
        return None

    async def save_capability_flags(self, sub_id: str, flags: Any) -> None:
        """No-op save."""


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="cloudguardiq",
        description="CloudGuardIQ -- Azure CSPM + FinOps scanner",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan an Azure subscription")
    scan_parser.add_argument(
        "--subscription-id",
        required=True,
        help="Azure subscription ID to scan",
    )
    scan_parser.add_argument(
        "--output",
        choices=["json", "table"],
        default="json",
        help="Output format (default: json)",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.command == "scan":
        asyncio.run(_run_scan(args.subscription_id, args.output))


if __name__ == "__main__":
    main()
