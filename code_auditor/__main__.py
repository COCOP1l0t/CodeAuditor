from __future__ import annotations

import argparse
import sys

from .db import AuditStore, DEFAULT_DB_PATH
from .repos import DEFAULT_RESULTS_DIR
from .review_cleanup import (
    ReviewedCleanupError,
    apply_reviewed_cleanup,
    build_reviewed_cleanup_report,
)
from .utils import render_json_report

_MAINTENANCE_COMMANDS = (
    (
        "maintenance_status_dry_run",
        lambda _root, db_path=DEFAULT_DB_PATH: AuditStore(db_path).repair_maintenance_statuses(),
        ValueError,
    ),
    (
        "maintenance_status_apply",
        lambda _root, db_path=DEFAULT_DB_PATH: AuditStore(db_path).repair_maintenance_statuses(apply=True),
        ValueError,
    ),
    (
        "reviewed_cleanup_dry_run",
        build_reviewed_cleanup_report,
        ReviewedCleanupError,
    ),
    (
        "reviewed_cleanup_apply",
        apply_reviewed_cleanup,
        ReviewedCleanupError,
    ),
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="code-auditor",
        description="Web-based multi-stage code auditing agent application",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Web UI bind host (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Web UI bind port (default: 8000)",
    )
    cleanup_group = parser.add_mutually_exclusive_group()
    cleanup_group.add_argument(
        "--maintenance-status-dry-run",
        nargs="?",
        const="",
        metavar="IGNORED",
        help="report stale PoC-backfill statuses without changing history",
    )
    cleanup_group.add_argument(
        "--maintenance-status-apply",
        nargs="?",
        const="",
        metavar="IGNORED",
        help="repair stale PoC-backfill statuses in history",
    )
    cleanup_group.add_argument(
        "--reviewed-cleanup-dry-run",
        nargs="?",
        const=DEFAULT_RESULTS_DIR,
        metavar="RESULTS_ROOT",
        help=(
            "plan deletion of compilation directories only for reproduced bugs "
            "whose SQLite review status is not unreviewed"
        ),
    )
    cleanup_group.add_argument(
        "--reviewed-cleanup-apply",
        nargs="?",
        const=DEFAULT_RESULTS_DIR,
        metavar="RESULTS_ROOT",
        help=(
            "delete compilation directories accepted by a fresh reviewed cleanup "
            "plan; preserves registered and retained artifacts"
        ),
    )
    return parser


def _exit_after_keyboard_interrupt() -> None:
    print("\nInterrupted by user.", file=sys.stderr)
    sys.exit(130)


def _run_web(args: argparse.Namespace) -> None:
    from .web import run_web_server

    try:
        run_web_server(args.host, args.port)
    except KeyboardInterrupt:
        _exit_after_keyboard_interrupt()


def _run_maintenance_command(
    args: argparse.Namespace,
) -> bool | None:
    """Dispatch the selected read/write maintenance mode, if any."""
    for attribute, handler, error_type in _MAINTENANCE_COMMANDS:
        results_root = getattr(args, attribute)
        if results_root is None:
            continue
        try:
            report = handler(results_root, db_path=DEFAULT_DB_PATH)
        except error_type as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return False
        print(render_json_report(report), end="")
        return True
    return None


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    maintenance_succeeded = _run_maintenance_command(args)
    if maintenance_succeeded is not None:
        if not maintenance_succeeded:
            sys.exit(1)
        return

    _run_web(args)


if __name__ == "__main__":
    main()
