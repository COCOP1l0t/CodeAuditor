from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

from .config import (
    DEFAULT_AGENT_TIMEOUT_SECONDS,
    DEFAULT_BACKEND,
    DEFAULT_CLAUDE_MODEL,
    DEFAULT_CODEX_MODEL,
    UNLIMITED_AU_COUNT,
    AuditConfig,
    resolve_wiki_arg,
)
from .db import DEFAULT_DB_PATH, RUN_CANCELLED, RUN_DONE, RUN_FAILED
from .logger import configure_logging, get_logger
from .orchestrator import run_audit
from .repos import DEFAULT_RESULTS_DIR, default_audit_output_dir, ensure_repo_sync
from .review_cleanup import (
    ReviewedCleanupError,
    apply_reviewed_cleanup,
    build_reviewed_cleanup_report,
)
from .retention_migration import (
    RetentionMigrationError,
    apply_retention_entrypoint_repairs,
    apply_retention_manifests,
    build_retention_entrypoint_repair_report,
    build_retention_migration_report,
)
from .tui import TUIManager
from .utils import render_json_report, summarize_task_errors

logger = get_logger("main")

_MAINTENANCE_COMMANDS = (
    (
        "retention_migration_dry_run",
        "--retention-migration-dry-run",
        build_retention_migration_report,
        RetentionMigrationError,
    ),
    (
        "retention_manifest_apply",
        "--retention-manifest-apply",
        apply_retention_manifests,
        RetentionMigrationError,
    ),
    (
        "retention_entrypoint_repair_dry_run",
        "--retention-entrypoint-repair-dry-run",
        build_retention_entrypoint_repair_report,
        RetentionMigrationError,
    ),
    (
        "retention_entrypoint_repair_apply",
        "--retention-entrypoint-repair-apply",
        apply_retention_entrypoint_repairs,
        RetentionMigrationError,
    ),
    (
        "reviewed_cleanup_dry_run",
        "--reviewed-cleanup-dry-run",
        build_reviewed_cleanup_report,
        ReviewedCleanupError,
    ),
    (
        "reviewed_cleanup_apply",
        "--reviewed-cleanup-apply",
        apply_reviewed_cleanup,
        ReviewedCleanupError,
    ),
)


def _persist_run_safely(
    db_path: str,
    config: AuditConfig,
    status: str,
    error: str,
    started_at: float,
) -> None:
    """Record a finished run in the history DB; never breaks the CLI flow."""
    try:
        from .db import AuditStore

        store = AuditStore(db_path)
        store.record_run(config, status=status, error=error, started_at=started_at)
    except Exception as e:
        logger.warning("Failed to record audit run in history database: %s", e)


def _seed_aus_safely(db_path: str, config: AuditConfig) -> None:
    """Reuse analysis units from a previous audit of the same repo+commit."""
    try:
        from .db import AuditStore, compute_target_key
        from .repos import capture_repo_identity

        store = AuditStore(db_path)
        target_key = compute_target_key(capture_repo_identity(config.target))
        seeded = store.seed_analysis_units(target_key, config.output_dir)
        if seeded:
            logger.info(
                "Reused %d analysis units from a previous audit of this commit.",
                seeded,
            )
    except Exception as e:
        logger.warning("Failed to seed analysis units: %s", e)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="code-auditor",
        description="Multi-stage code auditing agent application",
    )
    parser.add_argument("--target", help="Root directory of the project to audit (required unless --web or --repo-url)")
    parser.add_argument(
        "--repo-url",
        help="Git repository URL to clone into ~/.code-auditor/repos/ and audit",
    )
    parser.add_argument("--output-dir", help="Output directory (default: ~/.code_auditor/results/{repo}/audit-output-{commit})")
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
    parser.add_argument("--target-au-count", type=int, default=UNLIMITED_AU_COUNT, help="Target number of analysis units for stage 2 (default: -1 = no ceiling)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Launch the interactive TUI dashboard",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch the web UI (audit parameters are entered in the browser)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Web UI bind host (default: 127.0.0.1; use 0.0.0.0 to expose on the network)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Web UI bind port (default: 8000)",
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_DB_PATH,
        help=f"Audit history SQLite database path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--sandbox-image",
        default=os.environ.get("CODE_AUDITOR_SANDBOX_IMAGE", "code-auditor-sandbox:latest"),
        help="Docker image used for Stage 5/6 compilation and reproduction",
    )
    parser.add_argument(
        "--sandbox-root",
        default=os.environ.get("CODE_AUDITOR_SANDBOX_ROOT", "/tmp/code-auditor"),
        help="Disposable Stage 5/6 scratch root; must be a dedicated directory under /tmp",
    )
    parser.add_argument(
        "--no-docker-sandbox",
        action="store_true",
        help="Disable the Stage 5/6 Docker boundary (unsafe; intended only for controlled debugging)",
    )
    retention_group = parser.add_mutually_exclusive_group()
    retention_group.add_argument(
        "--retention-migration-dry-run",
        nargs="?",
        const=DEFAULT_RESULTS_DIR,
        metavar="RESULTS_ROOT",
        help=(
            "scan historical results and print a retain-manifest migration plan; "
            f"never writes or deletes files (default root: {DEFAULT_RESULTS_DIR})"
        ),
    )
    retention_group.add_argument(
        "--retention-manifest-apply",
        nargs="?",
        const=DEFAULT_RESULTS_DIR,
        metavar="RESULTS_ROOT",
        help=(
            "create or repair only manifests accepted by the historical migration "
            f"plan; never deletes artifacts (default root: {DEFAULT_RESULTS_DIR})"
        ),
    )
    retention_group.add_argument(
        "--retention-entrypoint-repair-dry-run",
        nargs="?",
        const=DEFAULT_RESULTS_DIR,
        metavar="RESULTS_ROOT",
        help=(
            "plan canonical reproduce.sh wrappers for unambiguous portable legacy "
            "entrypoints; never writes files"
        ),
    )
    retention_group.add_argument(
        "--retention-entrypoint-repair-apply",
        nargs="?",
        const=DEFAULT_RESULTS_DIR,
        metavar="RESULTS_ROOT",
        help=(
            "create proven-safe reproduce.sh wrappers and validated retain "
            "manifests; never deletes artifacts"
        ),
    )
    retention_group.add_argument(
        "--reviewed-cleanup-dry-run",
        nargs="?",
        const=DEFAULT_RESULTS_DIR,
        metavar="RESULTS_ROOT",
        help=(
            "plan deletion of compilation directories only for reproduced bugs "
            "whose SQLite review status is not unreviewed"
        ),
    )
    retention_group.add_argument(
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


def _resolve_wiki_path(path: str | None) -> str | None:
    try:
        return resolve_wiki_arg(path)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def _exit_after_keyboard_interrupt() -> None:
    print("\nInterrupted by user.", file=sys.stderr)
    sys.exit(130)


def _run_web(args: argparse.Namespace) -> None:
    from .web import run_web_server

    defaults = {
        "git_url": args.repo_url,
        "db_path": args.db,
    }
    try:
        run_web_server(args.host, args.port, defaults)
    except KeyboardInterrupt:
        _exit_after_keyboard_interrupt()


def _run_maintenance_command(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> bool | None:
    """Dispatch the selected read/write maintenance mode, if any."""
    for attribute, flag, handler, error_type in _MAINTENANCE_COMMANDS:
        results_root = getattr(args, attribute)
        if results_root is None:
            continue
        if args.web or args.target or args.repo_url:
            parser.error(f"{flag} cannot be combined with an audit or --web")
        try:
            report = handler(results_root, db_path=args.db)
        except error_type as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return False
        print(render_json_report(report), end="")
        return True
    return None


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    maintenance_succeeded = _run_maintenance_command(args, parser)
    if maintenance_succeeded is not None:
        if not maintenance_succeeded:
            sys.exit(1)
        return

    if args.web:
        _run_web(args)
        return

    if not args.target and not args.repo_url:
        parser.error("--target is required unless --web or --repo-url is used")

    if args.repo_url:
        from .repos import RepoError

        try:
            target = ensure_repo_sync(args.repo_url)
        except RepoError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        target = os.path.realpath(args.target)
        if not os.path.isdir(target):
            print(f"Error: Target directory not found: {target}", file=sys.stderr)
            sys.exit(1)

    output_dir = os.path.realpath(args.output_dir or default_audit_output_dir(target))
    wiki_path = _resolve_wiki_path(args.wiki)

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
        agent_timeout_seconds=DEFAULT_AGENT_TIMEOUT_SECONDS,
        sandbox_enabled=not args.no_docker_sandbox,
        sandbox_image=args.sandbox_image,
        sandbox_root=args.sandbox_root,
    )

    if args.tui:
        # TUI mode: Textual live dashboard
        tui = TUIManager()
        tui.configure(
            target=config.target,
            output_dir=config.output_dir,
            wiki_path=config.wiki_path,
            backend=config.backend,
            model=config.model,
            max_parallel=config.max_parallel,
        )
        configure_logging(config.log_level)

        async def run_tui_audit() -> None:
            if config.wiki_path:
                logger.info("Loaded wiki knowledge base: %s", config.wiki_path)
            logger.info("Starting audit of %s", config.target)
            started_at = time.time()
            status, error = RUN_DONE, ""
            try:
                _seed_aus_safely(args.db, config)
                await run_audit(config, tui=tui)
                error = summarize_task_errors(config.task_errors)
                status = RUN_FAILED if error else RUN_DONE
            except asyncio.CancelledError:
                status = RUN_CANCELLED
                raise
            except Exception as e:
                status, error = RUN_FAILED, str(e)
                raise
            finally:
                _persist_run_safely(args.db, config, status, error, started_at)

        failed, interrupted = tui.run_audit(run_tui_audit)
        if interrupted:
            _exit_after_keyboard_interrupt()
        if failed:
            sys.exit(1)
    else:
        # Classic mode: plain log output
        configure_logging(config.log_level)
        if config.wiki_path:
            logger.info("Loaded wiki knowledge base: %s", config.wiki_path)
        logger.info("Starting audit of %s", config.target)

        started_at = time.time()
        try:
            _seed_aus_safely(args.db, config)
            asyncio.run(run_audit(config))
            print("\nAudit complete.")
        except KeyboardInterrupt:
            _persist_run_safely(args.db, config, RUN_CANCELLED, "", started_at)
            _exit_after_keyboard_interrupt()
        except Exception as e:
            _persist_run_safely(args.db, config, RUN_FAILED, str(e), started_at)
            print(f"\nError: {e}", file=sys.stderr)
            sys.exit(1)
        task_error_summary = summarize_task_errors(config.task_errors)
        _persist_run_safely(
            args.db,
            config,
            RUN_FAILED if task_error_summary else RUN_DONE,
            task_error_summary,
            started_at,
        )


if __name__ == "__main__":
    main()
