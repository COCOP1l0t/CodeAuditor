from __future__ import annotations

import argparse
import asyncio
import os
import sys

from .config import (
    DEFAULT_BACKEND,
    DEFAULT_CLAUDE_MODEL,
    DEFAULT_CODEX_MODEL,
    AuditConfig,
)
from .logger import configure_logging, get_logger
from .orchestrator import run_audit
from .tui import TUIManager

logger = get_logger("main")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="code-auditor",
        description="Multi-stage code auditing agent application",
    )
    parser.add_argument("--target", required=True, help="Root directory of the project to audit")
    parser.add_argument("--output-dir", help="Output directory (default: {target}/audit-output)")
    parser.add_argument("--wiki", help="Read-only LLM wiki knowledge base directory")
    parser.add_argument("--max-parallel", type=int, default=1, help="Maximum concurrent agents (default: 1)")
    parser.add_argument(
        "--backend",
        choices=["claude", "codex"],
        default=DEFAULT_BACKEND,
        help="Agent backend to use (default: claude)",
    )
    parser.add_argument(
        "--model",
        help=f"Backend model override (Claude default: {DEFAULT_CLAUDE_MODEL}; Codex default: {DEFAULT_CODEX_MODEL})",
    )
    parser.add_argument("--target-au-count", type=int, default=10, help="Target number of analysis units for stage 2 (default: 10)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument(
        "--audit-only",
        action="store_true",
        help="Run only stages 1-4 (skip PoC reproduction and disclosure stages 5-6)",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Launch the interactive TUI dashboard",
    )
    return parser


def _resolve_wiki_path(path: str | None) -> str | None:
    if not path:
        return None

    resolved = os.path.realpath(path)
    if not os.path.exists(resolved):
        print(f"Error: Wiki directory not found: {resolved}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(resolved):
        print(f"Error: Wiki path is not a directory: {resolved}", file=sys.stderr)
        sys.exit(1)
    return resolved


def _exit_after_keyboard_interrupt() -> None:
    print("\nInterrupted by user.", file=sys.stderr)
    sys.exit(130)


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    target = os.path.realpath(args.target)
    if not os.path.isdir(target):
        print(f"Error: Target directory not found: {target}", file=sys.stderr)
        sys.exit(1)

    output_dir = os.path.realpath(args.output_dir or os.path.join(target, "audit-output"))
    wiki_path = _resolve_wiki_path(args.wiki)

    skip_stages = [5, 6] if args.audit_only else []

    config = AuditConfig(
        target=target,
        output_dir=output_dir,
        wiki_path=wiki_path,
        max_parallel=args.max_parallel,
        resume=True,
        log_level=args.log_level.upper(),
        backend=args.backend,
        model=args.model,
        target_au_count=args.target_au_count,
        skip_stages=skip_stages,
    )

    if args.tui:
        # TUI mode: Textual live dashboard
        tui = TUIManager()
        tui.configure(
            target=config.target,
            output_dir=config.output_dir,
            backend=config.backend,
            model=config.model,
            max_parallel=config.max_parallel,
        )
        configure_logging(config.log_level)

        async def run_tui_audit() -> None:
            logger.info("Starting audit of %s", config.target)
            await run_audit(config, tui=tui)

        failed, interrupted = tui.run_audit(run_tui_audit)
        if interrupted:
            _exit_after_keyboard_interrupt()
        if failed:
            sys.exit(1)
    else:
        # Classic mode: plain log output
        configure_logging(config.log_level)
        logger.info("Starting audit of %s", config.target)

        try:
            asyncio.run(run_audit(config))
            print("\nAudit complete.")
        except KeyboardInterrupt:
            _exit_after_keyboard_interrupt()
        except Exception as e:
            print(f"\nError: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
