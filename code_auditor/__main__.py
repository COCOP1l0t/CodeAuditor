from __future__ import annotations

import argparse
import asyncio
import os
import sys

from .config import AuditConfig
from .logger import configure_logging, get_logger
from .orchestrator import run_audit

logger = get_logger("main")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="code-auditor",
        description="Multi-stage code auditing agent application",
    )
    parser.add_argument("--target", required=True, help="Root directory of the project to audit")
    parser.add_argument("--output-dir", help="Output directory (default: {target}/audit-output)")
    parser.add_argument("--max-parallel", type=int, default=1, help="Maximum concurrent agents (default: 1)")
    parser.add_argument("--model", default="claude-sonnet-4-6", help="Claude model to use (default: claude-sonnet-4-6)")
    parser.add_argument("--target-au-count", type=int, default=10, help="Target number of analysis units for stage 3 (default: 10)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    target = os.path.realpath(args.target)
    if not os.path.isdir(target):
        print(f"Error: Target directory not found: {target}", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.realpath(args.output_dir or os.path.join(target, "audit-output"))

    config = AuditConfig(
        target=target,
        output_dir=output_dir,
        max_parallel=args.max_parallel,
        resume=True,
        log_level=args.log_level.upper(),
        model=args.model,
        target_au_count=args.target_au_count,
    )

    configure_logging(config.log_level)
    logger.info("Starting audit of %s", config.target)

    try:
        asyncio.run(run_audit(config))
        print("\nAudit complete.")
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
