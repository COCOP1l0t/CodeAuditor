from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

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
    parser.add_argument(
        "--validate-trajectory",
        metavar="PATH",
        help=(
            "validate the ATIF trajectories under PATH (a JSON file or a results "
            "tree) and exit with 0 when every document is valid"
        ),
    )
    return parser


def _trajectory_base(path: Path) -> Path | None:
    """Nearest ``trajectories`` ancestor, the base for relative child refs."""
    for parent in (path.parent, *path.parents):
        if parent.name == "trajectories":
            return parent
    return None


def _reference_problems(path: Path, document: dict) -> list[str]:
    """Validate ``trajectory_path``/``trajectory_id`` references of one file."""
    base = _trajectory_base(path)
    if base is None:
        return []
    embedded = {
        sub.get("trajectory_id")
        for sub in document.get("subagent_trajectories") or []
        if isinstance(sub, dict)
    }
    problems: list[str] = []
    steps = document.get("steps")
    if not isinstance(steps, list):
        return problems
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        observation = step.get("observation")
        results = observation.get("results") if isinstance(observation, dict) else None
        if not isinstance(results, list):
            continue
        for result_index, result in enumerate(results):
            if not isinstance(result, dict):
                continue
            refs = result.get("subagent_trajectory_ref")
            if not isinstance(refs, list):
                continue
            for ref_index, ref in enumerate(refs):
                if not isinstance(ref, dict):
                    continue
                prefix = (
                    f"steps[{index}].observation.results[{result_index}]"
                    f".subagent_trajectory_ref[{ref_index}]"
                )
                target_value = ref.get("trajectory_path")
                if isinstance(target_value, str) and target_value:
                    target = (base / target_value).resolve()
                    try:
                        target.relative_to(base.resolve())
                    except ValueError:
                        problems.append(
                            f"{prefix}.trajectory_path escapes {base.name}/: "
                            f"{target_value}"
                        )
                        continue
                    if not target.is_file():
                        problems.append(
                            f"{prefix}.trajectory_path does not exist: {target_value}"
                        )
                    continue
                trajectory_id = ref.get("trajectory_id")
                if trajectory_id and trajectory_id not in embedded:
                    problems.append(
                        f"{prefix}.trajectory_id is not embedded: {trajectory_id}"
                    )
    return problems


def _validate_trajectories(path_value: str) -> bool:
    """Validate ATIF documents; prints one JSON report and returns success."""
    from .trajectory import validate_trajectory

    root = Path(path_value)
    if not root.exists():
        print(f"Error: no such path: {root}", file=sys.stderr)
        return False
    tree_mode = root.is_dir()
    if not tree_mode:
        files = [root]
    else:
        files = sorted(
            path
            for path in root.rglob("*.json")
            if path.is_file()
            and ("trajectories" in path.parts or path.name.startswith("trajectory"))
        )
    entries = []
    documents: list[tuple[Path, dict, dict]] = []
    for path in files[:2000]:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            entries.append({"path": str(path), "valid": False, "problems": [str(exc)]})
            continue
        problems = validate_trajectory(document)
        entry: dict = {"path": str(path), "valid": not problems, "problems": problems}
        entries.append(entry)
        if isinstance(document, dict):
            documents.append((path, document, entry))
    # Reference integrity is only meaningful when the whole tree was supplied.
    if tree_mode:
        for path, document, entry in documents:
            problems = _reference_problems(path, document)
            if problems:
                entry["problems"] = list(entry.get("problems") or []) + problems
                entry["valid"] = False
    valid = sum(1 for entry in entries if entry["valid"])
    report = {
        "checked": len(entries),
        "valid": valid,
        "invalid": len(entries) - valid,
        "truncated": len(files) > 2000,
        "files": entries,
    }
    print(render_json_report(report), end="")
    return valid == len(entries)


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

    if args.validate_trajectory is not None:
        sys.exit(0 if _validate_trajectories(args.validate_trajectory) else 1)

    maintenance_succeeded = _run_maintenance_command(args)
    if maintenance_succeeded is not None:
        if not maintenance_succeeded:
            sys.exit(1)
        return

    _run_web(args)


if __name__ == "__main__":
    main()
