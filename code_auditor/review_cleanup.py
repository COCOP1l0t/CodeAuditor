"""Review-status-gated cleanup of historical compilation directories."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .db import DISCLOSURE_REVIEW_STATUSES
from .retention import (
    DISPOSABLE_DIRECTORY_NAMES,
    RETAIN_MANIFEST_FILENAME,
    RetentionError,
    allocated_tree_bytes,
    find_audit_output_dirs,
    load_retain_manifest,
)

CLEANUP_REPORT_SCHEMA_VERSION = 1

_REVIEWED_STATUSES = DISCLOSURE_REVIEW_STATUSES - {"unreviewed"}
_KEY_FILENAMES = frozenset(
    {
        RETAIN_MANIFEST_FILENAME,
        "asan-report.txt",
        "disclosure.zip",
        "email.txt",
        "report.md",
        "reproduce.sh",
        "trigger-graph.json",
    }
)


class ReviewedCleanupError(ValueError):
    """Raised when reviewed cleanup cannot prove that a target is disposable."""


def _is_disposable_directory_name(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered in DISPOSABLE_DIRECTORY_NAMES
        or lowered.startswith(("build-", "build_", "cmake-build-", "pip-"))
        or lowered.endswith("-build")
        or "-build-" in lowered
    )


def _resolve_results_root(results_root: str | os.PathLike[str]) -> Path:
    unresolved = Path(results_root).expanduser()
    if unresolved.is_symlink():
        raise ReviewedCleanupError(f"results root cannot be a symlink: {unresolved}")
    root = unresolved.resolve()
    if not root.is_dir():
        raise ReviewedCleanupError(f"results root is missing or unsafe: {root}")
    return root


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        return path == root or path.is_relative_to(root)
    except (OSError, ValueError):
        return False


def _registered_path(output: Path, value: object) -> Path | None:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = output / candidate
    resolved = candidate.resolve()
    return resolved if _path_is_within(resolved, output) else None


def _database_state(
    db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    resolved = Path(db_path).expanduser().resolve()
    if not resolved.is_file():
        raise ReviewedCleanupError(f"audit database is missing: {resolved}")
    try:
        connection = sqlite3.connect(f"file:{resolved}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            if quick_check != "ok":
                raise ReviewedCleanupError(
                    f"audit database quick_check failed: {quick_check}"
                )
            active_outputs = {
                os.path.realpath(os.path.expanduser(str(row[0])))
                for row in connection.execute(
                    "SELECT output_dir FROM runs WHERE status = 'running'"
                ).fetchall()
                if row and row[0]
            }
            mappings = connection.execute(
                """
                SELECT r.output_dir, v.vuln_id, p.status AS poc_status,
                       disclosed_bugs.review_status
                FROM vulnerabilities v
                JOIN runs r ON r.id = v.run_id
                LEFT JOIN pocs p
                  ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                LEFT JOIN disclosed_bugs
                  ON disclosed_bugs.dedupe_key = v.dedupe_key
                """
            ).fetchall()
            registered_rows = connection.execute(
                """
                SELECT r.output_dir, p.report_path, p.trigger_graph_path,
                       p.asan_report_path, NULL AS email_path, NULL AS zip_path
                FROM pocs p JOIN runs r ON r.id = p.run_id
                UNION ALL
                SELECT r.output_dir, d.report_path, NULL, NULL,
                       d.email_path, d.zip_path
                FROM disclosures d JOIN runs r ON r.id = d.run_id
                """
            ).fetchall()
            artifact_link_rows = connection.execute(
                "SELECT artifact_links FROM disclosed_bugs"
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise ReviewedCleanupError(f"cannot read audit database: {exc}") from exc

    by_artifact: dict[tuple[str, str], list[dict[str, str | None]]] = defaultdict(list)
    for row in mappings:
        by_artifact[
            (os.path.realpath(str(row["output_dir"])), str(row["vuln_id"]))
        ].append(
            {
                "poc_status": row["poc_status"],
                "review_status": row["review_status"],
            }
        )

    registered_paths: set[Path] = set()
    for row in registered_rows:
        output = Path(os.path.realpath(str(row["output_dir"])))
        for key in (
            "report_path",
            "trigger_graph_path",
            "asan_report_path",
            "email_path",
            "zip_path",
        ):
            candidate = _registered_path(output, row[key])
            if candidate is not None:
                registered_paths.add(candidate)
    for row in artifact_link_rows:
        try:
            links = json.loads(row["artifact_links"] or "[]")
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(links, list):
            continue
        for item in links:
            if not isinstance(item, dict):
                continue
            value = item.get("path")
            if isinstance(value, str) and value and "\x00" not in value:
                registered_paths.add(Path(value).expanduser().resolve())
    return {
        "path": str(resolved),
        "active_outputs": active_outputs,
        "by_artifact": by_artifact,
        "registered_paths": registered_paths,
    }


def _review_gate(
    mappings: Iterable[dict[str, str | None]],
) -> tuple[str, list[str]]:
    entries = list(mappings)
    reproduced = [entry for entry in entries if entry["poc_status"] == "reproduced"]
    if not entries:
        return "unmapped", []
    if not reproduced:
        return "not_reproduced", []
    statuses = {entry["review_status"] for entry in reproduced}
    if None in statuses or any(status not in DISCLOSURE_REVIEW_STATUSES for status in statuses):
        return "review_unknown", sorted(str(status) for status in statuses)
    if "unreviewed" in statuses:
        return "unreviewed", sorted(str(status) for status in statuses)
    normalized = sorted(str(status) for status in statuses)
    if statuses and statuses.issubset(_REVIEWED_STATUSES):
        return "eligible_non_unreviewed", normalized
    return "review_unknown", normalized


def _artifact_directories(output: Path) -> list[tuple[str, str, Path]]:
    artifacts: list[tuple[str, str, Path]] = []
    stage5 = output / "stage5-pocs"
    if stage5.is_dir() and not stage5.is_symlink():
        for path in sorted(stage5.iterdir(), key=lambda item: item.name):
            if path.is_dir() and not path.is_symlink():
                artifacts.append((path.name.removesuffix("_fp"), "stage5", path))
    stage6 = output / "stage6-disclosures"
    if stage6.is_dir() and not stage6.is_symlink():
        for vuln_dir in sorted(stage6.iterdir(), key=lambda item: item.name):
            disclosure = vuln_dir / "disclosure"
            if disclosure.is_dir() and not disclosure.is_symlink():
                artifacts.append((vuln_dir.name, "stage6", disclosure))
    return artifacts


def _artifact_cleanup_candidates(
    artifact: Path,
    *,
    kind: str,
) -> list[Path]:
    candidates: list[Path] = []
    for current, dirs, _files in os.walk(artifact, topdown=True, followlinks=False):
        current_path = Path(current)
        safe_dirs: list[str] = []
        for name in sorted(dirs):
            path = current_path / name
            if path.is_symlink():
                continue
            if _is_disposable_directory_name(name):
                candidates.append(path)
            else:
                safe_dirs.append(name)
        dirs[:] = safe_dirs
    if kind == "stage6":
        vuln_dir = artifact.parent
        for child in sorted(vuln_dir.iterdir(), key=lambda item: item.name):
            if child == artifact or child.is_symlink() or not child.is_dir():
                continue
            if _is_disposable_directory_name(child.name):
                candidates.append(child)
    return candidates


def _manifest_paths(artifact: Path) -> set[Path]:
    manifest_path = artifact / RETAIN_MANIFEST_FILENAME
    if not manifest_path.exists():
        return set()
    try:
        manifest = load_retain_manifest(artifact)
    except RetentionError:
        return {manifest_path.resolve()}
    paths = {manifest_path.resolve()}
    paths.update((artifact / item.path).resolve() for item in manifest.files)
    return paths


def _target_blockers(target: Path, protected_paths: set[Path]) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    for protected in sorted(protected_paths, key=str):
        if _path_is_within(protected, target):
            blockers.append({"type": "registered_or_retained_path", "path": str(protected)})
    for current, dirs, files in os.walk(target, topdown=True, followlinks=False):
        current_path = Path(current)
        dirs[:] = [
            name
            for name in sorted(dirs)
            if not (current_path / name).is_symlink()
        ]
        for name in sorted(files):
            if name.lower() in _KEY_FILENAMES:
                blockers.append(
                    {
                        "type": "key_filename",
                        "path": str((current_path / name).resolve()),
                    }
                )
    return blockers


def build_reviewed_cleanup_report(
    results_root: str | os.PathLike[str],
    *,
    db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Build a read-only cleanup plan gated by reproduced bug review status."""
    root = _resolve_results_root(results_root)
    database = _database_state(db_path)
    active_outputs: set[str] = database["active_outputs"]
    mappings = database["by_artifact"]
    registered_paths: set[Path] = database["registered_paths"]
    artifact_counts: Counter[str] = Counter()
    target_candidates: list[dict[str, Any]] = []
    blocked_targets: list[dict[str, Any]] = []

    for output in find_audit_output_dirs(root):
        artifacts = _artifact_directories(output)
        artifact_states: list[tuple[str, str, Path, str, list[str]]] = []
        for vuln_id, kind, artifact in artifacts:
            gate, statuses = _review_gate(mappings.get((str(output), vuln_id), ()))
            if str(output) in active_outputs:
                gate = "active_output"
            artifact_counts[f"{kind}:{gate}"] += 1
            artifact_states.append((vuln_id, kind, artifact, gate, statuses))

        if artifacts and all(state[3] == "eligible_non_unreviewed" for state in artifact_states):
            shared_protected = set(registered_paths)
            for _vuln_id, _kind, artifact, _gate, _statuses in artifact_states:
                shared_protected.update(_manifest_paths(artifact))
            for name in (".poc-worktree", "toolchain"):
                target = output / name
                if target.is_dir() and not target.is_symlink():
                    item = {
                        "path": str(target),
                        "scope": "shared-output",
                        "output": str(output),
                        "vuln_id": "",
                        "artifact": "",
                        "review_statuses": sorted(
                            {status for state in artifact_states for status in state[4]}
                        ),
                    }
                    blockers = _target_blockers(target, shared_protected)
                    if blockers:
                        item["blockers"] = blockers
                        item["allocated_bytes"] = allocated_tree_bytes(target)
                        blocked_targets.append(item)
                    else:
                        target_candidates.append(item)

        for vuln_id, kind, artifact, gate, statuses in artifact_states:
            if gate != "eligible_non_unreviewed":
                continue
            protected = registered_paths | _manifest_paths(artifact)
            for target in _artifact_cleanup_candidates(artifact, kind=kind):
                item = {
                    "path": str(target.resolve()),
                    "scope": "artifact",
                    "output": str(output),
                    "vuln_id": vuln_id,
                    "artifact": str(artifact),
                    "artifact_kind": kind,
                    "review_statuses": statuses,
                }
                blockers = _target_blockers(target, protected)
                if blockers:
                    item["blockers"] = blockers
                    item["allocated_bytes"] = allocated_tree_bytes(target)
                    blocked_targets.append(item)
                else:
                    target_candidates.append(item)

    selected_targets: list[dict[str, Any]] = []
    for item in sorted(
        target_candidates,
        key=lambda value: (len(Path(value["path"]).parts), value["path"]),
    ):
        path = Path(item["path"])
        if any(_path_is_within(path, Path(parent["path"])) for parent in selected_targets):
            continue
        item["allocated_bytes"] = allocated_tree_bytes(path)
        selected_targets.append(item)

    return {
        "schema_version": CLEANUP_REPORT_SCHEMA_VERSION,
        "mode": "dry-run",
        "results_root": str(root),
        "database": {
            "path": database["path"],
            "verified": True,
            "active_output_count": len(active_outputs),
        },
        "summary": {
            "artifact_status_counts": dict(sorted(artifact_counts.items())),
            "cleanup_target_count": len(selected_targets),
            "blocked_target_count": len(blocked_targets),
            "estimated_reclaimable_bytes": sum(
                int(item["allocated_bytes"]) for item in selected_targets
            ),
        },
        "targets": selected_targets,
        "blocked_targets": blocked_targets,
        "mutations": [],
    }


def _assert_safe_target(target: Path, root: Path) -> None:
    if target.is_symlink() or not target.is_dir():
        raise ReviewedCleanupError(f"cleanup target changed type or is missing: {target}")
    resolved = target.resolve()
    if resolved != target or not _path_is_within(resolved, root):
        raise ReviewedCleanupError(f"cleanup target escapes results root: {target}")
    relative = resolved.relative_to(root)
    if len(relative.parts) < 3:
        raise ReviewedCleanupError(f"refusing broad cleanup target: {target}")


def _revalidate_target(
    item: dict[str, Any],
    *,
    root: Path,
    db_path: str | os.PathLike[str],
) -> None:
    database = _database_state(db_path)
    if database["active_outputs"]:
        raise ReviewedCleanupError("an audit became active during cleanup")
    output = Path(item["output"]).resolve()
    if not _path_is_within(output, root):
        raise ReviewedCleanupError(f"cleanup output escapes results root: {output}")
    mappings = database["by_artifact"]
    protected_paths: set[Path] = set(database["registered_paths"])
    if item["scope"] == "artifact":
        gate, statuses = _review_gate(
            mappings.get((str(output), str(item["vuln_id"])), ())
        )
        if gate != "eligible_non_unreviewed" or statuses != item["review_statuses"]:
            raise ReviewedCleanupError(
                f"review status changed for cleanup target: {item['path']}"
            )
        artifact = Path(item["artifact"])
        protected_paths.update(_manifest_paths(artifact))
    elif item["scope"] == "shared-output":
        artifact_states = []
        for vuln_id, _kind, artifact in _artifact_directories(output):
            gate, statuses = _review_gate(mappings.get((str(output), vuln_id), ()))
            artifact_states.append((gate, statuses, artifact))
        if not artifact_states or any(
            gate != "eligible_non_unreviewed" for gate, _statuses, _artifact in artifact_states
        ):
            raise ReviewedCleanupError(
                f"shared output is no longer fully reviewed: {output}"
            )
        for _gate, _statuses, artifact in artifact_states:
            protected_paths.update(_manifest_paths(artifact))
    else:
        raise ReviewedCleanupError(f"unsupported cleanup scope: {item['scope']}")
    target = Path(item["path"])
    if not _is_disposable_directory_name(target.name) and target.name not in {
        ".poc-worktree",
        "toolchain",
    }:
        raise ReviewedCleanupError(f"cleanup target name is not disposable: {target}")
    blockers = _target_blockers(target, protected_paths)
    if blockers:
        raise ReviewedCleanupError(
            f"cleanup target gained protected files: {target}: {blockers[0]}"
        )


def apply_reviewed_cleanup(
    results_root: str | os.PathLike[str],
    *,
    db_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Delete only compilation directories from non-unreviewed reproduced bugs."""
    report = build_reviewed_cleanup_report(results_root, db_path=db_path)
    if report["database"]["active_output_count"]:
        raise ReviewedCleanupError("refusing cleanup while an audit output is active")
    root = Path(report["results_root"])
    mutations: list[dict[str, Any]] = []
    for item in report["targets"]:
        target = Path(item["path"])
        _revalidate_target(item, root=root, db_path=db_path)
        _assert_safe_target(target, root)
        allocated_bytes = allocated_tree_bytes(target)
        shutil.rmtree(target)
        mutations.append(
            {
                "action": "delete-directory",
                "path": str(target),
                "allocated_bytes": allocated_bytes,
                "vuln_id": item["vuln_id"],
                "review_statuses": item["review_statuses"],
            }
        )
    report["mode"] = "apply"
    report["mutations"] = mutations
    report["summary"]["actual_reclaimed_bytes"] = sum(
        int(item["allocated_bytes"]) for item in mutations
    )
    return report
