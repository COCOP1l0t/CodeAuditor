from __future__ import annotations

import argparse
import asyncio
import os
import sys

from .config import DEFAULT_CLAUDE_MODEL, DEFAULT_CODEX_MODEL, AuditConfig
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
    parser.add_argument("--model", help="Agent model to use (default depends on --agent-backend)")
    parser.add_argument("--target-au-count", type=int, default=10, help="Target number of analysis units for stage 2 (default: 10)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument(
        "--agent-backend",
        default="claude-code",
        choices=["claude-code", "codex"],
        help="Agent runtime backend (default: claude-code)",
    )
    parser.add_argument("--codex-bin", help="Path to a codex binary for the Codex app-server backend")
    parser.add_argument(
        "--codex-sdk-path",
        help="Path to codex-main/sdk/python or an installed SDK source directory for local Codex SDK use",
    )
    parser.add_argument(
        "--codex-sandbox",
        default="workspace-write",
        choices=["read-only", "workspace-write", "danger-full-access"],
        help="Codex sandbox mode (default: workspace-write)",
    )
    parser.add_argument(
        "--codex-network-access",
        action="store_true",
        help="Allow network access for Codex workspace-write/read-only sandbox policies",
    )
    parser.add_argument(
        "--codex-extra-writable-root",
        action="append",
        default=[],
        help="Additional writable root for the Codex workspace-write sandbox; may be repeated",
    )
    parser.add_argument(
        "--audit-only",
        action="store_true",
        help="Run only stages 1-4 (skip PoC reproduction and disclosure stages 5-6)",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    target = os.path.realpath(args.target)
    if not os.path.isdir(target):
        print(f"Error: Target directory not found: {target}", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.realpath(args.output_dir or os.path.join(target, "audit-output"))
    model = args.model or (DEFAULT_CODEX_MODEL if args.agent_backend == "codex" else DEFAULT_CLAUDE_MODEL)

    skip_stages = [5, 6] if args.audit_only else []

    config = AuditConfig(
        target=target,
        output_dir=output_dir,
        max_parallel=args.max_parallel,
        resume=True,
        log_level=args.log_level.upper(),
        model=model,
        target_au_count=args.target_au_count,
        skip_stages=skip_stages,
        agent_backend=args.agent_backend,
        codex_bin=args.codex_bin,
        codex_sdk_path=os.path.realpath(args.codex_sdk_path) if args.codex_sdk_path else None,
        codex_sandbox=args.codex_sandbox,
        codex_network_access=args.codex_network_access,
        codex_extra_writable_roots=[os.path.realpath(p) for p in args.codex_extra_writable_root],
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
