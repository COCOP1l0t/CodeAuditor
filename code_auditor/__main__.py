from __future__ import annotations

import argparse
import asyncio
import os
import sys

from .config import DEFAULT_THREAT_MODEL, AuditConfig
from .logger import configure_logging, get_logger
from .orchestrator import run_audit

logger = get_logger("main")


_ALL_STAGES = list(range(6))  # 0–5


def _parse_skip_stages(raw: str | None) -> list[int]:
    if not raw:
        return []
    values = [v.strip() for v in raw.split(",") if v.strip()]
    try:
        return [int(v) for v in values]
    except ValueError:
        raise argparse.ArgumentTypeError("--skip-stages must be a comma-separated list of integers.")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="code-auditor",
        description="Multi-stage code auditing agent application",
    )
    parser.add_argument("--target", required=True, help="Root directory of the project to audit")
    parser.add_argument("--output-dir", help="Output directory (default: {target}/audit-output)")
    parser.add_argument("--max-parallel", type=int, default=4, help="Maximum concurrent agents (default: 4)")
    parser.add_argument("--resume", action="store_true", help="Resume from previous output files and markers")
    parser.add_argument("--threat-model", default=DEFAULT_THREAT_MODEL, help="Override the default threat model")
    parser.add_argument("--scope", default="", help="Additional scope instructions for stage 1")
    parser.add_argument("--skip-stages", default=None, help="Comma-separated list of stages to skip")
    parser.add_argument("--only-stage", type=int, choices=_ALL_STAGES, default=None,
                        help="Run only this stage (stage 0 always runs for setup)")
    parser.add_argument("--model", default="claude-sonnet-4-6", help="Claude model to use (default: claude-sonnet-4-6)")
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

    if args.only_stage is not None and args.skip_stages is not None:
        print("Error: --only-stage and --skip-stages are mutually exclusive.", file=sys.stderr)
        sys.exit(1)

    if args.only_stage is not None:
        skip_stages = [s for s in _ALL_STAGES if s != 0 and s != args.only_stage]
    else:
        skip_stages = _parse_skip_stages(args.skip_stages)

    config = AuditConfig(
        target=target,
        output_dir=output_dir,
        max_parallel=args.max_parallel,
        threat_model=args.threat_model,
        scope=args.scope,
        skip_stages=skip_stages,
        resume=args.resume,
        log_level=args.log_level.upper(),
        model=args.model,
    )

    configure_logging(config.log_level)
    logger.info("Starting audit of %s", config.target)

    try:
        report_path = asyncio.run(run_audit(config))
        print(f"\nAudit complete. Report: {report_path}")
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
