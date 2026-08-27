"""Read-only planning for migrating historical PoC trees to retention manifests."""
from __future__ import annotations

import json
import hashlib
import os
import re
import sqlite3
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator
from uuid import uuid4

from .retention import (
    DEFAULT_RETAIN_MAX_FILE_BYTES,
    DEFAULT_RETAIN_MAX_TOTAL_BYTES,
    DISPOSABLE_DIRECTORY_NAMES,
    MAX_RETAIN_FILES,
    RETAIN_MANIFEST_FILENAME,
    RetentionError,
    allocated_tree_bytes,
    find_audit_output_dirs,
    load_retain_manifest,
    validate_retain_manifest_data,
)

MIGRATION_REPORT_SCHEMA_VERSION = 1

_LEGACY_ENTRYPOINT_NAMES = frozenset(
    {
        "build-and-run.sh",
        "build_and_run.sh",
        "poc.sh",
        "repro.sh",
        "run-poc.sh",
        "run-repro.sh",
        "run_poc.sh",
        "run_repro.sh",
        "run_reproducer.sh",
        "run_reproduction.sh",
    }
)

_DISPOSABLE_COMPONENTS = DISPOSABLE_DIRECTORY_NAMES | {
    ".git",
    "obj",
    "qemu-worktree",
    "repro-worktree",
}
_SCRIPT_SUFFIXES = frozenset(
    {".sh", ".py", ".pl", ".rb", ".ps1", ".js", ".ts"}
)
_SUPPORT_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cfg",
        ".conf",
        ".cpp",
        ".diff",
        ".h",
        ".ini",
        ".json",
        ".ovf",
        ".patch",
        ".rs",
        ".toml",
        ".yaml",
        ".yml",
    }
)
_INPUT_SUFFIXES = frozenset({".mig", ".sav", ".vhd", ".vhdx", ".vmdk"})
_SUPPORT_NAMES = frozenset(
    {
        "Cargo.lock",
        "Cargo.toml",
        "Makefile",
        "package-lock.json",
        "package.json",
        "requirements.txt",
    }
)
_EVIDENCE_NAMES = frozenset({"asan-report.txt", "trigger-graph.json"})
_DISCLOSURE_NAMES = frozenset({"disclosure.zip", "email.txt"})
_REFERENCE_MARKERS = (
    ".poc-worktree",
    "/toolchain/",
    "/build-asan/",
    "/build-debug/",
    "/build-release/",
    "qemu-worktree",
    "repro-worktree",
    "/.code_auditor/results/",
    "/.code_auditor/repo/",
    "/tmp/code-auditor/",
)


class RetentionMigrationError(ValueError):
    """Raised when a dry-run history root or database is invalid."""


def _is_disposable(relative_path: str) -> bool:
    parts = PurePosixPath(relative_path).parts[:-1]
    for part in parts:
        lowered = part.lower()
        if lowered in _DISPOSABLE_COMPONENTS:
            return True
        if lowered.startswith(("build-", "build_", "cmake-build-", "pip-")):
            return True
    return False


def _candidate_role(relative_path: str) -> str | None:
    path = PurePosixPath(relative_path)
    name = path.name
    lowered = name.lower()
    suffix = path.suffix.lower()
    if lowered == "reproduce.sh":
        return "entrypoint"
    if lowered == "report.md":
        return "report"
    if lowered in _EVIDENCE_NAMES:
        return "evidence"
    if lowered in _DISCLOSURE_NAMES:
        return "disclosure"
    if suffix in _SCRIPT_SUFFIXES:
        return "script"
    if suffix in _INPUT_SUFFIXES:
        return "input"
    if any(
        part.lower() in {"evidence", "poc-output"}
        for part in path.parts[:-1]
    ):
        return "evidence"
    if suffix in _SUPPORT_SUFFIXES or name in _SUPPORT_NAMES:
        return "support"
    return None


def _walk_files(root: Path) -> Iterator[tuple[str, Path, os.stat_result]]:
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        safe_dirs: list[str] = []
        for name in sorted(dirs):
            child = current_path / name
            try:
                child_stat = child.lstat()
            except OSError:
                continue
            if stat.S_ISDIR(child_stat.st_mode) and not stat.S_ISLNK(
                child_stat.st_mode
            ):
                safe_dirs.append(name)
        dirs[:] = safe_dirs
        for name in sorted(files):
            path = current_path / name
            try:
                file_stat = path.lstat()
            except OSError:
                continue
            relative_path = path.relative_to(root).as_posix()
            yield relative_path, path, file_stat


def _has_artifact_content(root: Path) -> bool:
    """Return whether a historical artifact directory contains any entry."""
    try:
        next(root.iterdir())
    except StopIteration:
        return False
    except OSError:
        # Let the normal planner surface unreadable content instead of silently
        # dropping an artifact from the migration inventory.
        return True
    return True


def _inode_key(file_stat: os.stat_result) -> tuple[int, int]:
    return file_stat.st_dev, file_stat.st_ino


def _allocated_bytes(file_stat: os.stat_result) -> int:
    return int(getattr(file_stat, "st_blocks", 0)) * 512


def _reference_blockers(path: Path, relative_path: str) -> list[dict[str, str]]:
    try:
        if path.stat().st_size > 4 * 1024 * 1024:
            return []
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    return [
        {"path": relative_path, "marker": marker}
        for marker in _REFERENCE_MARKERS
        if marker in content
    ]


def _existing_manifest_plan(root: Path) -> dict[str, Any] | None:
    if not (root / RETAIN_MANIFEST_FILENAME).exists():
        return None
    try:
        manifest = load_retain_manifest(root)
    except RetentionError as exc:
        return {
            "state": "invalid",
            "error": str(exc),
            "entrypoint": None,
            "files": [],
            "retained_bytes": 0,
        }
    return {
        "state": "valid",
        "error": "",
        "entrypoint": manifest.entrypoint,
        "files": [
            {"path": retained.path, "role": retained.role, "size": retained.size}
            for retained in manifest.files
        ],
        "retained_bytes": manifest.total_bytes,
    }


def _plan_artifact(root: Path, *, kind: str) -> dict[str, Any]:
    existing = _existing_manifest_plan(root)
    all_inodes: dict[tuple[int, int], int] = {}
    retained_inodes: set[tuple[int, int]] = set()
    proposed: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    references: list[dict[str, str]] = []
    apparent_retained_bytes = 0
    executable_entrypoint = False

    existing_roles = (
        {item["path"]: item["role"] for item in existing["files"]}
        if existing and existing["state"] == "valid"
        else {}
    )

    for relative_path, path, file_stat in _walk_files(root):
        if stat.S_ISREG(file_stat.st_mode):
            all_inodes.setdefault(_inode_key(file_stat), _allocated_bytes(file_stat))
        if relative_path == RETAIN_MANIFEST_FILENAME:
            if existing and existing["state"] == "valid":
                retained_inodes.add(_inode_key(file_stat))
            continue
        if existing_roles:
            role = existing_roles.get(relative_path)
        elif _is_disposable(relative_path):
            role = None
        else:
            role = _candidate_role(relative_path)
        if role is None:
            continue
        if not stat.S_ISREG(file_stat.st_mode) or stat.S_ISLNK(file_stat.st_mode):
            blockers.append({"type": "unsafe_candidate", "path": relative_path})
            continue
        if file_stat.st_nlink != 1:
            blockers.append({"type": "hardlinked_candidate", "path": relative_path})
        if file_stat.st_size > DEFAULT_RETAIN_MAX_FILE_BYTES:
            blockers.append(
                {
                    "type": "oversized_candidate",
                    "path": relative_path,
                    "size": file_stat.st_size,
                }
            )
            continue
        proposed.append(
            {"path": relative_path, "role": role, "size": file_stat.st_size}
        )
        apparent_retained_bytes += file_stat.st_size
        retained_inodes.add(_inode_key(file_stat))
        if role in {"entrypoint", "script", "support"}:
            references.extend(_reference_blockers(path, relative_path))
        if relative_path == "reproduce.sh":
            executable_entrypoint = bool(file_stat.st_mode & stat.S_IXUSR)

    proposed.sort(key=lambda item: str(item["path"]))
    if len(proposed) > MAX_RETAIN_FILES:
        blockers.append(
            {"type": "too_many_candidates", "count": len(proposed)}
        )
    if apparent_retained_bytes > DEFAULT_RETAIN_MAX_TOTAL_BYTES:
        blockers.append(
            {
                "type": "retained_total_too_large",
                "size": apparent_retained_bytes,
            }
        )
    if "reproduce.sh" not in {item["path"] for item in proposed}:
        blockers.append({"type": "missing_reproduce_sh"})
    elif not executable_entrypoint:
        blockers.append({"type": "reproduce_sh_not_executable"})
    if not any(item["path"] == "report.md" for item in proposed):
        blockers.append({"type": "missing_report"})
    for reference in references:
        blockers.append({"type": "disposable_path_reference", **reference})
    required_paths = ["report.md", "reproduce.sh"]
    if kind == "stage6":
        required_paths.extend(("email.txt", "disclosure.zip"))
        proposed_paths = {item["path"] for item in proposed}
        if "email.txt" not in proposed_paths:
            blockers.append({"type": "missing_email"})
        if "disclosure.zip" not in proposed_paths:
            blockers.append({"type": "missing_disclosure_zip"})

    proposed_manifest = {
        "schema_version": 1,
        "entrypoint": "reproduce.sh",
        "files": [
            {"path": item["path"], "role": item["role"]}
            for item in proposed
        ],
    }
    if not blockers:
        try:
            validate_retain_manifest_data(
                root,
                proposed_manifest,
                required_paths=required_paths,
            )
        except RetentionError as exc:
            blockers.append(
                {"type": "manifest_validation_failed", "error": str(exc)}
            )

    existing_state = existing["state"] if existing else "missing"
    if existing_state == "valid":
        manifest_action = "none"
    elif existing_state == "invalid":
        manifest_action = "repair"
    else:
        manifest_action = "create"

    allocated_bytes = sum(all_inodes.values())
    retained_allocated_bytes = sum(
        size for key, size in all_inodes.items() if key in retained_inodes
    )
    return {
        "kind": kind,
        "path": str(root),
        "existing_manifest": existing or {"state": "missing"},
        "manifest_action": manifest_action,
        "proposed_manifest": proposed_manifest,
        "candidate_files": proposed,
        "allocated_bytes": allocated_bytes,
        "proposed_retained_allocated_bytes": retained_allocated_bytes,
        "estimated_reclaimable_bytes": max(
            allocated_bytes - retained_allocated_bytes, 0
        ),
        "ready": not blockers,
        "blockers": blockers,
    }


def _active_output_dirs(db_path: str | os.PathLike[str] | None) -> tuple[set[str], str]:
    if not db_path:
        return set(), "database path was not supplied"
    resolved = Path(db_path).expanduser().resolve()
    if not resolved.is_file():
        return set(), f"database is missing: {resolved}"
    try:
        connection = sqlite3.connect(f"file:{resolved}?mode=ro", uri=True)
        try:
            rows = connection.execute(
                "SELECT output_dir FROM runs WHERE status = 'running'"
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        return set(), f"cannot read database: {exc}"
    return {
        os.path.realpath(os.path.expanduser(str(row[0])))
        for row in rows
        if row and row[0]
    }, ""


def _poc_status_inventory(
    db_path: str | os.PathLike[str] | None,
) -> tuple[dict[tuple[str, str], set[str]] | None, str]:
    if not db_path:
        return None, "database path was not supplied"
    resolved = Path(db_path).expanduser().resolve()
    if not resolved.is_file():
        return None, f"database is missing: {resolved}"
    try:
        connection = sqlite3.connect(f"file:{resolved}?mode=ro", uri=True)
        try:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            if not {"pocs", "runs"}.issubset(tables):
                return None, "database does not contain PoC status history"
            rows = connection.execute(
                """
                SELECT r.output_dir, p.vuln_id, p.status
                FROM pocs p JOIN runs r ON r.id = p.run_id
                """
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        return None, f"cannot read PoC status history: {exc}"

    statuses: dict[tuple[str, str], set[str]] = {}
    for output_dir, vuln_id, poc_status in rows:
        if not output_dir or not vuln_id or not poc_status:
            continue
        key = (
            os.path.realpath(os.path.expanduser(str(output_dir))),
            str(vuln_id),
        )
        statuses.setdefault(key, set()).add(str(poc_status))
    return statuses, ""


def _apply_poc_status_gate(
    artifact: dict[str, Any],
    *,
    output: Path,
    vuln_id: str,
    statuses: dict[tuple[str, str], set[str]] | None,
) -> None:
    artifact["vuln_id"] = vuln_id
    known = (
        sorted(statuses.get((str(output), vuln_id), set()))
        if statuses is not None
        else []
    )
    artifact["poc_statuses"] = known
    artifact["migration_required"] = True
    artifact["migration_state"] = "required"
    if statuses is None:
        artifact["poc_status_gate"] = "unavailable"
        return
    artifact["poc_status_gate"] = "verified"
    if "reproduced" in known:
        return
    if known:
        artifact["migration_required"] = False
        artifact["migration_state"] = "exempt-not-reproduced"
        artifact["ignored_blockers"] = artifact["blockers"]
        artifact["blockers"] = []
        artifact["ready"] = True
        artifact["manifest_action"] = "none"
        return
    artifact["migration_state"] = "blocked-unmapped-poc-status"
    artifact["ready"] = False
    artifact["blockers"].append({"type": "poc_status_unmapped"})


def _apply_stage5_supersession(artifacts: list[dict[str, Any]]) -> None:
    retained_stage6 = {
        str(artifact["vuln_id"]): artifact
        for artifact in artifacts
        if artifact["kind"] == "stage6"
        and artifact.get("poc_status_gate") == "verified"
        and "reproduced" in artifact.get("poc_statuses", [])
        and artifact.get("migration_required", True)
        and artifact["ready"]
        and artifact["existing_manifest"].get("state") == "valid"
    }
    for artifact in artifacts:
        if (
            artifact["kind"] != "stage5"
            or not artifact.get("migration_required", True)
            or artifact["ready"]
            or artifact.get("poc_status_gate") != "verified"
            or "reproduced" not in artifact.get("poc_statuses", [])
        ):
            continue
        replacement = retained_stage6.get(str(artifact["vuln_id"]))
        if replacement is None:
            continue
        artifact["migration_required"] = False
        artifact["migration_state"] = "superseded-by-stage6"
        artifact["superseded_by"] = replacement["path"]
        artifact["ignored_blockers"] = artifact["blockers"]
        artifact["blockers"] = []
        artifact["ready"] = True
        artifact["manifest_action"] = "none"


def build_retention_migration_report(
    results_root: str | os.PathLike[str],
    *,
    db_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Return a deterministic migration plan without writing or deleting files."""
    unresolved_root = Path(results_root).expanduser()
    if unresolved_root.is_symlink():
        raise RetentionMigrationError(
            f"results root cannot be a symlink: {unresolved_root}"
        )
    root = unresolved_root.resolve()
    if not root.is_dir():
        raise RetentionMigrationError(f"results root is missing or unsafe: {root}")

    active_outputs, database_warning = _active_output_dirs(db_path)
    database_verified = not database_warning
    poc_statuses, poc_status_warning = _poc_status_inventory(db_path)
    output_plans: list[dict[str, Any]] = []
    total_artifacts = 0
    ready_artifacts = 0
    required_artifacts = 0
    exempt_artifacts = 0
    superseded_artifacts = 0
    reclaimable_bytes = 0
    disposable_bytes = 0

    for output in find_audit_output_dirs(root):
        artifacts: list[dict[str, Any]] = []
        stage5 = output / "stage5-pocs"
        if stage5.is_dir() and not stage5.is_symlink():
            for poc_dir in sorted(stage5.iterdir(), key=lambda path: path.name):
                if (
                    poc_dir.is_dir()
                    and not poc_dir.is_symlink()
                    and _has_artifact_content(poc_dir)
                ):
                    plan = _plan_artifact(poc_dir, kind="stage5")
                    _apply_poc_status_gate(
                        plan,
                        output=output,
                        vuln_id=poc_dir.name.removesuffix("_fp"),
                        statuses=poc_statuses,
                    )
                    artifacts.append(plan)

        stage6 = output / "stage6-disclosures"
        stage6_disposable_paths: list[dict[str, Any]] = []
        if stage6.is_dir() and not stage6.is_symlink():
            for vuln_dir in sorted(stage6.iterdir(), key=lambda path: path.name):
                if not vuln_dir.is_dir() or vuln_dir.is_symlink():
                    continue
                disclosure = vuln_dir / "disclosure"
                if (
                    disclosure.is_dir()
                    and not disclosure.is_symlink()
                    and _has_artifact_content(disclosure)
                ):
                    plan = _plan_artifact(disclosure, kind="stage6")
                    _apply_poc_status_gate(
                        plan,
                        output=output,
                        vuln_id=vuln_dir.name.removesuffix("_fp"),
                        statuses=poc_statuses,
                    )
                    artifacts.append(plan)
                for child in sorted(vuln_dir.iterdir(), key=lambda path: path.name):
                    if child == disclosure or child.is_symlink():
                        continue
                    if child.is_dir():
                        size = allocated_tree_bytes(child)
                    elif child.is_file():
                        size = _allocated_bytes(child.stat())
                    else:
                        continue
                    if size:
                        stage6_disposable_paths.append(
                            {
                                "path": str(child),
                                "kind": "stage6-non-disclosure-intermediate",
                                "allocated_bytes": size,
                            }
                        )

        _apply_stage5_supersession(artifacts)

        disposable_roots: list[dict[str, Any]] = []
        for name in (".poc-worktree", "toolchain"):
            candidate = output / name
            if candidate.is_dir() and not candidate.is_symlink():
                size = allocated_tree_bytes(candidate)
                disposable_roots.append(
                    {
                        "path": str(candidate),
                        "kind": name.lstrip("."),
                        "allocated_bytes": size,
                    }
                )
        disposable_roots.extend(stage6_disposable_paths)

        active = str(output) in active_outputs
        output_blocker = "active_output" if active else ""
        if not database_verified:
            output_blocker = "database_state_unknown"
        if output_blocker:
            for artifact in artifacts:
                artifact["ready"] = False
                artifact["blockers"].append({"type": output_blocker})
        disposable_blocker = output_blocker
        if not disposable_blocker and not artifacts:
            disposable_blocker = "no_retained_artifacts"
        if not disposable_blocker and any(
            artifact["migration_required"] and not artifact["ready"]
            for artifact in artifacts
        ):
            disposable_blocker = "artifact_migration_blocked"
        for disposable in disposable_roots:
            disposable["ready"] = not disposable_blocker
            if disposable_blocker:
                disposable["blocker"] = disposable_blocker
        total_artifacts += len(artifacts)
        required_artifacts += sum(
            1 for artifact in artifacts if artifact["migration_required"]
        )
        exempt_artifacts += sum(
            1
            for artifact in artifacts
            if artifact.get("migration_state") == "exempt-not-reproduced"
        )
        superseded_artifacts += sum(
            1
            for artifact in artifacts
            if artifact.get("migration_state") == "superseded-by-stage6"
        )
        ready_artifacts += sum(
            1
            for artifact in artifacts
            if artifact["migration_required"] and artifact["ready"]
        )
        artifact_reclaim = sum(
            artifact["estimated_reclaimable_bytes"] for artifact in artifacts
        )
        ready_artifact_reclaim = sum(
            artifact["estimated_reclaimable_bytes"]
            for artifact in artifacts
            if artifact["migration_required"] and artifact["ready"]
        )
        output_disposable_bytes = sum(
            item["allocated_bytes"] for item in disposable_roots
        )
        ready_output_disposable_bytes = sum(
            item["allocated_bytes"]
            for item in disposable_roots
            if item["ready"]
        )
        reclaimable_bytes += artifact_reclaim
        disposable_bytes += output_disposable_bytes
        output_plans.append(
            {
                "path": str(output),
                "active": active,
                "artifacts": artifacts,
                "disposable_roots": disposable_roots,
                "estimated_artifact_reclaimable_bytes": artifact_reclaim,
                "estimated_ready_artifact_reclaimable_bytes": ready_artifact_reclaim,
                "ready_disposable_root_bytes": ready_output_disposable_bytes,
            }
        )

    leftovers = root / "_merged-leftovers"
    leftover_bytes = allocated_tree_bytes(leftovers)
    ready_artifact_reclaimable_bytes = sum(
        output["estimated_ready_artifact_reclaimable_bytes"]
        for output in output_plans
    )
    ready_disposable_bytes = sum(
        output["ready_disposable_root_bytes"] for output in output_plans
    )

    return {
        "schema_version": MIGRATION_REPORT_SCHEMA_VERSION,
        "mode": "dry-run",
        "results_root": str(root),
        "database": {
            "path": str(Path(db_path).expanduser().resolve()) if db_path else None,
            "verified": database_verified,
            "warning": database_warning,
            "active_output_count": len(active_outputs),
            "poc_status_gate_verified": poc_statuses is not None,
            "poc_status_warning": poc_status_warning,
        },
        "summary": {
            "output_count": len(output_plans),
            "artifact_count": total_artifacts,
            "migration_required_artifact_count": required_artifacts,
            "exempt_not_reproduced_artifact_count": exempt_artifacts,
            "superseded_stage5_artifact_count": superseded_artifacts,
            "ready_artifact_count": ready_artifacts,
            "blocked_artifact_count": required_artifacts - ready_artifacts,
            "estimated_artifact_reclaimable_bytes": reclaimable_bytes,
            "disposable_root_bytes": disposable_bytes,
            "unregistered_leftover_bytes": leftover_bytes,
            "estimated_potential_reclaimable_bytes": (
                reclaimable_bytes + disposable_bytes + leftover_bytes
            ),
            "estimated_safe_reclaimable_bytes": (
                ready_artifact_reclaimable_bytes + ready_disposable_bytes
            ),
        },
        "outputs": output_plans,
        "unregistered_leftovers": {
            "path": str(leftovers),
            "allocated_bytes": leftover_bytes,
            "ready": False,
            "blocker": "manual_review_required",
        },
        "mutations": [],
    }


def _atomic_write_manifest(root: Path, manifest: dict[str, Any]) -> None:
    destination = root / RETAIN_MANIFEST_FILENAME
    pending = root / f".{RETAIN_MANIFEST_FILENAME}.pending-{uuid4().hex}"
    payload = (
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(pending, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(pending, destination)
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        pending.unlink(missing_ok=True)


def _entrypoint_wrapper(legacy_name: str) -> bytes:
    return _entrypoint_wrapper_with_interpreter(legacy_name, None)


def _entrypoint_wrapper_with_interpreter(
    legacy_name: str,
    interpreter: str | None,
) -> bytes:
    path = PurePosixPath(legacy_name)
    if (
        path.is_absolute()
        or path.as_posix() != legacy_name
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise RetentionMigrationError(f"unsafe legacy entrypoint path: {legacy_name}")
    if interpreter is not None and interpreter not in {
        "bash",
        "node",
        "perl",
        "python3",
        "ruby",
        "sh",
    }:
        raise RetentionMigrationError(
            f"unsupported legacy entrypoint interpreter: {interpreter}"
        )
    invocation = (
        f'{interpreter} "$SCRIPT_DIR/{legacy_name}"'
        if interpreter
        else f'"$SCRIPT_DIR/{legacy_name}"'
    )
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        'SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
        f'exec {invocation} "$@"\n'
    ).encode("utf-8")


def _supported_shebang_interpreter(content: bytes) -> str | None:
    first_line = content.splitlines()[0].decode("utf-8", errors="replace")
    for interpreter in ("python3", "bash", "node", "perl", "ruby", "sh"):
        if re.search(rf"(?:^|[/\s]){interpreter}(?:\s|$)", first_line):
            return interpreter
    return None


def _entrypoint_file_metadata(
    root: Path,
    relative_path: str,
    *,
    source: str,
) -> dict[str, Any]:
    path = root / relative_path
    try:
        file_stat = path.lstat()
    except OSError as exc:
        return {
            "name": relative_path,
            "source": source,
            "safe": False,
            "error": str(exc),
        }
    safe = (
        stat.S_ISREG(file_stat.st_mode)
        and not stat.S_ISLNK(file_stat.st_mode)
        and file_stat.st_nlink == 1
        and file_stat.st_size <= DEFAULT_RETAIN_MAX_FILE_BYTES
    )
    item: dict[str, Any] = {
        "name": relative_path,
        "source": source,
        "safe": safe,
        "executable": bool(file_stat.st_mode & stat.S_IXUSR),
        "size": file_stat.st_size,
        "mode": stat.S_IMODE(file_stat.st_mode),
    }
    if safe:
        try:
            content = path.read_bytes()
            item["sha256"] = hashlib.sha256(content).hexdigest()
            item["has_shebang"] = content.startswith(b"#!")
            item["interpreter"] = (
                _supported_shebang_interpreter(content)
                if item["has_shebang"]
                else None
            )
        except OSError as exc:
            item["safe"] = False
            item["error"] = str(exc)
    return item


def _report_references_script(report: str, relative_path: str) -> bool:
    invocation = "./" + relative_path
    pattern = rf"(^|[\s`(']){re.escape(invocation)}(?=$|[\s`'\";|&>)])"
    return re.search(pattern, report, flags=re.MULTILINE) is not None


def _looks_like_reproduction_script(relative_path: str) -> bool:
    name = PurePosixPath(relative_path).name.lower()
    return (
        any(marker in name for marker in ("poc", "repro", "trigger"))
        or name in {"run.py", "run.sh"}
    )


def _legacy_entrypoint_metadata(
    root: Path,
    candidate_files: Iterable[dict[str, Any]] = (),
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for name in sorted(_LEGACY_ENTRYPOINT_NAMES):
        path = root / name
        if not path.exists() and not path.is_symlink():
            continue
        candidates.append(
            _entrypoint_file_metadata(
                root,
                name,
                source="recognized-name",
            )
        )
    if candidates:
        return candidates

    nested_recognized = sorted(
        {
            str(item["path"])
            for item in candidate_files
            if item.get("role") == "script"
            and PurePosixPath(str(item["path"])).name.lower()
            in _LEGACY_ENTRYPOINT_NAMES
        }
    )
    if len(nested_recognized) == 1:
        return [
            _entrypoint_file_metadata(
                root,
                nested_recognized[0],
                source="recognized-nested-name",
            )
        ]

    try:
        report = (root / "report.md").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    referenced_paths = sorted(
        {
            str(item["path"])
            for item in candidate_files
            if item.get("role") == "script"
            and _looks_like_reproduction_script(str(item["path"]))
            and _report_references_script(report, str(item["path"]))
        }
    )
    if not referenced_paths:
        script_paths = sorted(
            {
                str(item["path"])
                for item in candidate_files
                if item.get("role") == "script"
            }
        )
        if len(script_paths) == 1 and _looks_like_reproduction_script(
            script_paths[0]
        ):
            referenced_paths = script_paths
            source = "unique-reproduction-script"
        else:
            source = "report-invocation"
    else:
        source = "report-invocation"
    for relative_path in referenced_paths:
        candidates.append(
            _entrypoint_file_metadata(
                root,
                relative_path,
                source=source,
            )
        )
    return candidates


def _entrypoint_repair_hint(blocker_type: str) -> str:
    hints = {
        "active_output": "wait for the audit output to become inactive",
        "database_state_unknown": "restore a readable audit database before writing",
        "disposable_path_reference": (
            "replace the referenced worktree/build path with a retained relative file "
            "or a CODE_AUDITOR_SOURCE/CODE_AUDITOR_WORK input"
        ),
        "missing_disclosure_zip": "restore the disclosure bundle before retention",
        "missing_email": "restore the disclosure email before retention",
        "missing_report": "restore report.md before retention",
        "too_many_candidates": "narrow the manifest to the files required by reproduction",
        "unsafe_candidate": "replace symlink or special candidates with regular files",
    }
    return hints.get(blocker_type, "resolve the migration blocker before retention")


def build_retention_entrypoint_repair_report(
    results_root: str | os.PathLike[str],
    *,
    db_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Plan canonical reproduce.sh wrappers without changing history."""
    migration = build_retention_migration_report(results_root, db_path=db_path)
    repairs: list[dict[str, Any]] = []
    blocked_artifacts: list[dict[str, Any]] = []
    auto_repairable = 0
    portability_blocked = 0
    invalid_manifests = 0

    for output in migration["outputs"]:
        for artifact in output["artifacts"]:
            if not artifact.get("migration_required", True):
                continue
            blocker_types = {
                str(blocker["type"]) for blocker in artifact["blockers"]
            }
            if not artifact["ready"]:
                if "disposable_path_reference" in blocker_types:
                    portability_blocked += 1
                if artifact["existing_manifest"]["state"] == "invalid":
                    invalid_manifests += 1
                blocked_artifacts.append(
                    {
                        "path": artifact["path"],
                        "output": output["path"],
                        "kind": artifact["kind"],
                        "existing_manifest": artifact["existing_manifest"],
                        "blockers": artifact["blockers"],
                        "recommended_fixes": sorted(
                            {
                                _entrypoint_repair_hint(blocker_type)
                                for blocker_type in blocker_types
                            }
                        ),
                    }
                )
            if "missing_reproduce_sh" not in blocker_types:
                continue
            root = Path(artifact["path"])
            legacy = _legacy_entrypoint_metadata(
                root,
                artifact["candidate_files"],
            )
            repair_blockers: list[dict[str, Any]] = []
            if not legacy:
                repair_blockers.append(
                    {
                        "type": "no_legacy_entrypoint",
                        "recommended_fix": (
                            "restore one executable reproducer or author reproduce.sh"
                        ),
                    }
                )
            elif len(legacy) != 1:
                repair_blockers.append(
                    {
                        "type": "ambiguous_legacy_entrypoint",
                        "count": len(legacy),
                        "recommended_fix": (
                            "choose one complete reproducer and make it the canonical entry"
                        ),
                    }
                )
            else:
                candidate = legacy[0]
                if not candidate.get("safe"):
                    repair_blockers.append(
                        {
                            "type": "unsafe_legacy_entrypoint",
                            "name": candidate["name"],
                            "recommended_fix": "replace it with a regular non-hardlinked file",
                        }
                    )
                elif not candidate.get("executable") and not candidate.get(
                    "interpreter"
                ):
                    repair_blockers.append(
                        {
                            "type": "legacy_entrypoint_not_executable",
                            "name": candidate["name"],
                            "recommended_fix": (
                                "verify the script, add a shebang, then make it owner-executable"
                            ),
                        }
                    )
                elif not candidate.get("has_shebang"):
                    repair_blockers.append(
                        {
                            "type": "legacy_entrypoint_missing_shebang",
                            "name": candidate["name"],
                            "recommended_fix": (
                                "add the interpreter shebang used by the documented command"
                            ),
                        }
                    )

            remaining = sorted(blocker_types - {"missing_reproduce_sh"})
            for blocker_type in remaining:
                repair_blockers.append(
                    {
                        "type": "artifact_blocker",
                        "blocker": blocker_type,
                        "recommended_fix": _entrypoint_repair_hint(blocker_type),
                    }
                )

            if len(legacy) == 1:
                interpreter = (
                    str(legacy[0]["interpreter"])
                    if not legacy[0].get("executable")
                    and legacy[0].get("interpreter")
                    else None
                )
                wrapper_size = len(
                    _entrypoint_wrapper_with_interpreter(
                        legacy[0]["name"],
                        interpreter,
                    )
                )
                if len(artifact["candidate_files"]) + 1 > MAX_RETAIN_FILES:
                    repair_blockers.append(
                        {"type": "wrapper_would_exceed_file_limit"}
                    )
                retained_size = sum(
                    int(candidate["size"])
                    for candidate in artifact["candidate_files"]
                )
                if retained_size + wrapper_size > DEFAULT_RETAIN_MAX_TOTAL_BYTES:
                    repair_blockers.append(
                        {"type": "wrapper_would_exceed_size_limit"}
                    )

            ready = not repair_blockers
            if ready:
                auto_repairable += 1
            repairs.append(
                {
                    "path": str(root),
                    "output": output["path"],
                    "kind": artifact["kind"],
                    "action": "create-wrapper" if ready else "manual-repair",
                    "ready": ready,
                    "legacy_entrypoints": legacy,
                    "artifact_blockers": [
                        blocker
                        for blocker in artifact["blockers"]
                        if blocker["type"] != "missing_reproduce_sh"
                    ],
                    "blockers": repair_blockers,
                }
            )

    return {
        "schema_version": MIGRATION_REPORT_SCHEMA_VERSION,
        "mode": "entrypoint-repair-dry-run",
        "results_root": migration["results_root"],
        "database": migration["database"],
        "summary": {
            "missing_entrypoint_count": len(repairs),
            "auto_repairable_count": auto_repairable,
            "manual_repair_count": len(repairs) - auto_repairable,
            "blocked_artifact_count": len(blocked_artifacts),
            "portability_blocked_count": portability_blocked,
            "invalid_manifest_count": invalid_manifests,
        },
        "repairs": repairs,
        "blocked_artifacts": blocked_artifacts,
        "mutations": [],
    }


def _atomic_create_entrypoint(
    root: Path,
    legacy_name: str,
    *,
    interpreter: str | None = None,
) -> None:
    destination = root / "reproduce.sh"
    pending = root / f".reproduce.sh.pending-{uuid4().hex}"
    payload = _entrypoint_wrapper_with_interpreter(legacy_name, interpreter)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(pending, flags, 0o700)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(pending, destination, follow_symlinks=False)
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        pending.unlink(missing_ok=True)


def apply_retention_entrypoint_repairs(
    results_root: str | os.PathLike[str],
    *,
    db_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Create unambiguous wrappers, then create their validated manifests."""
    initial = build_retention_entrypoint_repair_report(
        results_root,
        db_path=db_path,
    )
    if not initial["database"]["verified"]:
        raise RetentionMigrationError(
            "refusing to repair entrypoints without a verified audit database: "
            + str(initial["database"]["warning"])
        )

    mutations: list[dict[str, str]] = []
    for repair in initial["repairs"]:
        if not repair["ready"]:
            continue
        root = Path(repair["path"])
        current_plan = _plan_artifact(root, kind=repair["kind"])
        current_legacy = _legacy_entrypoint_metadata(
            root,
            current_plan["candidate_files"],
        )
        if current_legacy != repair["legacy_entrypoints"]:
            raise RetentionMigrationError(
                f"legacy entrypoint changed while planning repair: {root}"
            )
        active_outputs, warning = _active_output_dirs(db_path)
        if warning:
            raise RetentionMigrationError(
                "audit database changed while repairing entrypoints: " + warning
            )
        if repair["output"] in active_outputs:
            raise RetentionMigrationError(
                f"audit output became active while repairing entrypoints: {repair['output']}"
            )
        if (root / "reproduce.sh").exists() or (root / "reproduce.sh").is_symlink():
            raise RetentionMigrationError(
                f"canonical entrypoint appeared while planning repair: {root}"
            )
        legacy_name = str(current_legacy[0]["name"])
        interpreter = (
            str(current_legacy[0]["interpreter"])
            if not current_legacy[0].get("executable")
            and current_legacy[0].get("interpreter")
            else None
        )
        try:
            _atomic_create_entrypoint(
                root,
                legacy_name,
                interpreter=interpreter,
            )
            current = _plan_artifact(root, kind=repair["kind"])
        except OSError as exc:
            raise RetentionMigrationError(
                f"cannot create canonical entrypoint for {root}: {exc}"
            ) from exc
        if not current["ready"]:
            raise RetentionMigrationError(
                f"canonical entrypoint did not produce a valid migration plan: {root}"
            )
        mutations.append(
            {"action": "create-wrapper", "path": str(root / "reproduce.sh")}
        )

    manifest_report = apply_retention_manifests(results_root, db_path=db_path)
    manifest_mutations = list(manifest_report["mutations"])
    final = build_retention_entrypoint_repair_report(
        results_root,
        db_path=db_path,
    )
    final["mode"] = "apply-entrypoints-and-manifests"
    final["mutations"] = mutations + manifest_mutations
    final["summary"]["entrypoint_mutation_count"] = len(mutations)
    final["summary"]["manifest_mutation_count"] = len(manifest_mutations)
    return final


def apply_retention_manifests(
    results_root: str | os.PathLike[str],
    *,
    db_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Create or repair only manifests proven safe by a fresh migration plan."""
    initial = build_retention_migration_report(results_root, db_path=db_path)
    if not initial["database"]["verified"]:
        raise RetentionMigrationError(
            "refusing to write manifests without a verified audit database: "
            + str(initial["database"]["warning"])
        )

    mutations: list[dict[str, str]] = []
    for output in initial["outputs"]:
        for artifact in output["artifacts"]:
            action = artifact["manifest_action"]
            if (
                not artifact.get("migration_required", True)
                or not artifact["ready"]
                or action not in {"create", "repair"}
            ):
                continue
            root = Path(artifact["path"])
            current = _plan_artifact(root, kind=artifact["kind"])
            if (
                not current["ready"]
                or current["manifest_action"] != action
                or current["proposed_manifest"] != artifact["proposed_manifest"]
            ):
                raise RetentionMigrationError(
                    f"artifact changed while planning manifest migration: {root}"
                )
            required_paths = ["report.md", "reproduce.sh"]
            if artifact["kind"] == "stage6":
                required_paths.extend(("email.txt", "disclosure.zip"))
            try:
                validate_retain_manifest_data(
                    root,
                    current["proposed_manifest"],
                    required_paths=required_paths,
                )
                _atomic_write_manifest(root, current["proposed_manifest"])
                load_retain_manifest(root, required_paths=required_paths)
            except (OSError, RetentionError) as exc:
                raise RetentionMigrationError(
                    f"cannot {action} retain manifest for {root}: {exc}"
                ) from exc
            mutations.append(
                {
                    "action": action,
                    "path": str(root / RETAIN_MANIFEST_FILENAME),
                }
            )

    final = build_retention_migration_report(results_root, db_path=db_path)
    final["mode"] = "apply-manifests"
    final["mutations"] = mutations
    final["summary"]["manifest_mutation_count"] = len(mutations)
    return final
