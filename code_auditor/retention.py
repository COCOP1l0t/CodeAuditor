"""Validation and atomic export for bounded PoC retention manifests."""
from __future__ import annotations

import json
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
from uuid import uuid4

from .config import DEFAULT_RETAIN_MAX_FILE_BYTES, DEFAULT_RETAIN_MAX_TOTAL_BYTES

RETAIN_MANIFEST_FILENAME = "retain-manifest.json"
RETAIN_MANIFEST_SCHEMA_VERSION = 1
MAX_RETAIN_MANIFEST_BYTES = 256 * 1024
MAX_RETAIN_FILES = 256
DISPOSABLE_DIRECTORY_NAMES = frozenset(
    {
        ".cache",
        ".dart_tool",
        ".gradle",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "cache",
        "deps",
        "node_modules",
        "qemu-bundle",
        "sandbox",
        "target",
        "toolchain",
        "venv",
    }
)
_PORTABLE_TEXT_ROLES = frozenset({"entrypoint", "script", "support"})
_FORBIDDEN_PORTABLE_MARKERS = (
    b"/tmp/code-auditor/",
    b"/.code_auditor/repo/",
    b"/.code_auditor/results/",
    b"/.poc-worktree/",
    b".poc-worktree/",
    b"qemu-worktree",
    b"repro-worktree",
    b"/toolchain/",
)
ALLOWED_RETAIN_ROLES = frozenset(
    {
        "entrypoint",
        "script",
        "support",
        "report",
        "evidence",
        "input",
        "disclosure",
    }
)


class RetentionError(ValueError):
    """Raised when retained artifacts do not satisfy the export contract."""


def secure_generated_manifest_mode(
    artifact_dir: str | os.PathLike[str],
) -> bool:
    """Make an isolated agent's regular manifest owner-only before validation.

    The sandbox root is already owner-only, but agents commonly create text
    files with the process umask (0644).  Tightening a single, known manifest
    is deterministic output finalization; unsafe links and multiply-linked
    files are left untouched so the normal validator still rejects them.
    """
    path = Path(artifact_dir) / RETAIN_MANIFEST_FILENAME
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return False
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
            return False
        os.fchmod(fd, 0o600)
        return True
    finally:
        os.close(fd)


@dataclass(frozen=True)
class RetainedFile:
    path: str
    role: str
    size: int


@dataclass(frozen=True)
class RetainManifest:
    entrypoint: str
    files: tuple[RetainedFile, ...]
    total_bytes: int


def allocated_tree_bytes(root: Path) -> int:
    """Count allocated bytes for regular files without following links."""
    if not root.exists() or root.is_symlink():
        return 0
    total = 0
    seen: set[tuple[int, int]] = set()
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        dirs[:] = [
            name
            for name in sorted(dirs)
            if not (current_path / name).is_symlink()
        ]
        for name in sorted(files):
            path = current_path / name
            try:
                file_stat = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(file_stat.st_mode):
                continue
            inode = (file_stat.st_dev, file_stat.st_ino)
            if inode in seen:
                continue
            seen.add(inode)
            total += int(getattr(file_stat, "st_blocks", 0)) * 512
    return total


def find_audit_output_dirs(results_root: Path) -> list[Path]:
    """Find managed two-level ``audit-output-*`` directories safely."""
    outputs: list[Path] = []
    for project in sorted(results_root.iterdir(), key=lambda path: path.name):
        if (
            not project.is_dir()
            or project.is_symlink()
            or project.name == "_merged-leftovers"
        ):
            continue
        for candidate in sorted(project.iterdir(), key=lambda path: path.name):
            if (
                candidate.name.startswith("audit-output-")
                and candidate.is_dir()
                and not candidate.is_symlink()
            ):
                outputs.append(candidate.resolve())
    return outputs


def _safe_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise RetentionError("retained file paths must be non-empty strings")
    if "\\" in value or "\x00" in value:
        raise RetentionError(f"unsupported retained file path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise RetentionError(f"retained file path must be normalized and relative: {value!r}")
    normalized = path.as_posix()
    if normalized != value:
        raise RetentionError(f"retained file path must be normalized: {value!r}")
    return normalized


def _read_manifest_data(artifact_dir: Path) -> dict[str, Any]:
    manifest_path = artifact_dir / RETAIN_MANIFEST_FILENAME
    try:
        stat_result = manifest_path.lstat()
    except FileNotFoundError as exc:
        raise RetentionError(f"missing {RETAIN_MANIFEST_FILENAME}") from exc
    if not stat.S_ISREG(stat_result.st_mode) or stat.S_ISLNK(stat_result.st_mode):
        raise RetentionError(f"{RETAIN_MANIFEST_FILENAME} must be a regular file")
    if stat_result.st_nlink != 1:
        raise RetentionError(f"{RETAIN_MANIFEST_FILENAME} must not be hard-linked")
    if stat.S_IMODE(stat_result.st_mode) & 0o077:
        raise RetentionError(
            f"{RETAIN_MANIFEST_FILENAME} must not be group/world accessible"
        )
    if stat_result.st_size > MAX_RETAIN_MANIFEST_BYTES:
        raise RetentionError(
            f"{RETAIN_MANIFEST_FILENAME} exceeds {MAX_RETAIN_MANIFEST_BYTES} bytes"
        )
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetentionError(f"cannot read {RETAIN_MANIFEST_FILENAME}: {exc}") from exc
    if not isinstance(value, dict):
        raise RetentionError(f"{RETAIN_MANIFEST_FILENAME} must contain a JSON object")
    return value


def _regular_file_stat(root: Path, relative_path: str) -> os.stat_result:
    current = root
    parts = PurePosixPath(relative_path).parts
    for part in parts[:-1]:
        current = current / part
        try:
            current_stat = current.lstat()
        except FileNotFoundError as exc:
            raise RetentionError(f"retained file is missing: {relative_path}") from exc
        if not stat.S_ISDIR(current_stat.st_mode) or stat.S_ISLNK(current_stat.st_mode):
            raise RetentionError(
                f"retained file has a non-directory or symlink parent: {relative_path}"
            )

    path = root.joinpath(*parts)
    try:
        file_stat = path.lstat()
    except FileNotFoundError as exc:
        raise RetentionError(f"retained file is missing: {relative_path}") from exc
    if not stat.S_ISREG(file_stat.st_mode) or stat.S_ISLNK(file_stat.st_mode):
        raise RetentionError(f"retained path is not a regular file: {relative_path}")
    if file_stat.st_nlink != 1:
        raise RetentionError(f"retained path must not be hard-linked: {relative_path}")
    return file_stat


def _validate_portable_text(root: Path, relative_path: str, role: str) -> None:
    if role not in _PORTABLE_TEXT_ROLES:
        return
    path = root / relative_path
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise RetentionError(f"cannot read retained text file {relative_path}: {exc}") from exc
    if b"\0" in content:
        raise RetentionError(f"retained {role} must be a text file: {relative_path}")
    try:
        content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RetentionError(
            f"retained {role} must use UTF-8 encoding: {relative_path}"
        ) from exc
    for marker in _FORBIDDEN_PORTABLE_MARKERS:
        if marker in content:
            raise RetentionError(
                f"retained {role} references disposable CodeAuditor state "
                f"({marker.decode(errors='replace')}): {relative_path}"
            )


def load_retain_manifest(
    artifact_dir: str | os.PathLike[str],
    *,
    required_paths: Iterable[str] = (),
    max_file_bytes: int = DEFAULT_RETAIN_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_RETAIN_MAX_TOTAL_BYTES,
) -> RetainManifest:
    """Load and validate one bounded manifest without following symlinks."""
    root = Path(artifact_dir)
    if not root.is_dir() or root.is_symlink():
        raise RetentionError(f"artifact directory is missing or unsafe: {root}")

    data = _read_manifest_data(root)
    return validate_retain_manifest_data(
        root,
        data,
        required_paths=required_paths,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
    )


def validate_retain_manifest_data(
    artifact_dir: str | os.PathLike[str],
    data: dict[str, Any],
    *,
    required_paths: Iterable[str] = (),
    max_file_bytes: int = DEFAULT_RETAIN_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_RETAIN_MAX_TOTAL_BYTES,
) -> RetainManifest:
    """Validate proposed manifest data before it is committed to disk."""
    root = Path(artifact_dir)
    if not root.is_dir() or root.is_symlink():
        raise RetentionError(f"artifact directory is missing or unsafe: {root}")
    if not isinstance(data, dict):
        raise RetentionError(f"{RETAIN_MANIFEST_FILENAME} must contain a JSON object")
    if data.get("schema_version") != RETAIN_MANIFEST_SCHEMA_VERSION:
        raise RetentionError(
            f"schema_version must be {RETAIN_MANIFEST_SCHEMA_VERSION}"
        )
    entrypoint = _safe_relative_path(data.get("entrypoint"))
    if entrypoint != "reproduce.sh":
        raise RetentionError("entrypoint must be reproduce.sh")

    entries = data.get("files")
    if not isinstance(entries, list) or not entries:
        raise RetentionError("files must be a non-empty array")
    if len(entries) > MAX_RETAIN_FILES:
        raise RetentionError(f"files must contain at most {MAX_RETAIN_FILES} entries")

    retained: list[RetainedFile] = []
    seen: set[str] = set()
    total_bytes = 0
    entrypoint_role = ""
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise RetentionError(f"files[{index}] must be an object")
        relative_path = _safe_relative_path(entry.get("path"))
        role = entry.get("role")
        if role not in ALLOWED_RETAIN_ROLES:
            raise RetentionError(
                f"files[{index}].role must be one of: "
                + ", ".join(sorted(ALLOWED_RETAIN_ROLES))
            )
        if relative_path == RETAIN_MANIFEST_FILENAME:
            raise RetentionError(
                f"{RETAIN_MANIFEST_FILENAME} is retained automatically and must not be listed"
            )
        if relative_path in seen:
            raise RetentionError(f"duplicate retained file path: {relative_path}")
        seen.add(relative_path)
        if relative_path == entrypoint:
            entrypoint_role = str(role)

        file_stat = _regular_file_stat(root, relative_path)
        if file_stat.st_size > max_file_bytes:
            raise RetentionError(
                f"retained file exceeds {max_file_bytes} bytes: {relative_path}"
            )
        total_bytes += file_stat.st_size
        if total_bytes > max_total_bytes:
            raise RetentionError(
                f"retained files exceed the {max_total_bytes}-byte total limit"
            )
        retained.append(
            RetainedFile(
                path=relative_path,
                role=str(role),
                size=file_stat.st_size,
            )
        )
        _validate_portable_text(root, relative_path, str(role))

    if entrypoint not in seen or entrypoint_role != "entrypoint":
        raise RetentionError("reproduce.sh must be listed exactly once with role entrypoint")
    entrypoint_path = root / entrypoint
    try:
        first_line = entrypoint_path.open("rb").readline(256)
    except OSError as exc:
        raise RetentionError(f"cannot read reproduce.sh: {exc}") from exc
    if not first_line.startswith(b"#!"):
        raise RetentionError("reproduce.sh must start with a shebang")
    entrypoint_stat = _regular_file_stat(root, entrypoint)
    if not entrypoint_stat.st_mode & stat.S_IXUSR:
        raise RetentionError("reproduce.sh must be executable by its owner")

    required = {_safe_relative_path(path) for path in required_paths}
    missing = sorted(required - seen)
    if missing:
        raise RetentionError(
            "manifest does not retain required file(s): " + ", ".join(missing)
        )
    return RetainManifest(
        entrypoint=entrypoint,
        files=tuple(retained),
        total_bytes=total_bytes,
    )


def _copy_regular_file(source: Path, destination: Path) -> None:
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise RetentionError(f"retained source changed type during export: {source}")
        if source_stat.st_nlink != 1:
            raise RetentionError(f"retained source became hard-linked during export: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            stat.S_IMODE(source_stat.st_mode),
        )
        try:
            with os.fdopen(source_fd, "rb", closefd=False) as source_stream:
                with os.fdopen(destination_fd, "wb", closefd=False) as destination_stream:
                    shutil.copyfileobj(source_stream, destination_stream, length=1024 * 1024)
                    destination_stream.flush()
                    os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        os.chmod(destination, stat.S_IMODE(source_stat.st_mode))
    finally:
        os.close(source_fd)


def _ensure_safe_destination_parent(destination: Path) -> None:
    """Create destination parents without traversing a pre-existing symlink."""
    parts = destination.parent.parts
    if not parts:
        return
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o755)
            current_stat = current.lstat()
        if not stat.S_ISDIR(current_stat.st_mode) or stat.S_ISLNK(
            current_stat.st_mode
        ):
            raise RetentionError(
                f"destination parent must be a real directory: {current}"
            )


def export_retained_artifacts(
    artifact_dir: str | os.PathLike[str],
    destination_dir: str | os.PathLike[str],
    *,
    required_paths: Iterable[str] = (),
    max_file_bytes: int = DEFAULT_RETAIN_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_RETAIN_MAX_TOTAL_BYTES,
) -> RetainManifest:
    """Atomically replace a persistent artifact directory with retained files."""
    source = Path(artifact_dir)
    destination = Path(os.path.abspath(os.fspath(destination_dir)))
    manifest = load_retain_manifest(
        source,
        required_paths=required_paths,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
    )
    _ensure_safe_destination_parent(destination)
    try:
        destination_stat = destination.lstat()
    except FileNotFoundError:
        destination_stat = None
    if destination_stat is not None and (
        not stat.S_ISDIR(destination_stat.st_mode)
        or stat.S_ISLNK(destination_stat.st_mode)
    ):
        raise RetentionError(
            f"destination must be a real directory when it exists: {destination}"
        )

    staging = destination.parent / f".{destination.name}.retain-{uuid4().hex}"
    backup = destination.parent / f".{destination.name}.previous-{uuid4().hex}"
    staging.mkdir(mode=0o700)
    moved_previous = False
    try:
        for retained in manifest.files:
            _copy_regular_file(source / retained.path, staging / retained.path)
        _copy_regular_file(
            source / RETAIN_MANIFEST_FILENAME,
            staging / RETAIN_MANIFEST_FILENAME,
        )
        if destination.exists():
            os.replace(destination, backup)
            moved_previous = True
        try:
            os.replace(staging, destination)
        except Exception:
            if moved_previous and not destination.exists():
                os.replace(backup, destination)
                moved_previous = False
            raise
        if moved_previous:
            shutil.rmtree(backup)
            moved_previous = False
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if moved_previous and backup.exists() and not destination.exists():
            os.replace(backup, destination)
        elif backup.exists():
            shutil.rmtree(backup)
    return manifest
